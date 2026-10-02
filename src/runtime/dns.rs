//! Exit-side DNS forwarding. Only authenticated TUN requests can reach this port.
//! The kernel transparently redirects UDP/TCP 53 here and reverses that NAT for replies.
use super::resolver::MarkedRuntime;
use anyhow::{Result, ensure};
use hickory_resolver::proto::op::{Message, MessageType, OpCode, ResponseCode};
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::Semaphore,
    task::{JoinHandle, JoinSet},
};

pub(super) const PORT: u16 = 7353;
const QUERY_LIMIT: usize = 4096;
const TIMEOUT: Duration = Duration::from_secs(3);
pub(super) struct Forwarder {
    task: JoinHandle<()>,
}
impl Forwarder {
    pub fn start(servers: Vec<SocketAddr>, tun: &str) -> Result<Self> {
        ensure!(!servers.is_empty(), "Exit DNS requires upstream servers");
        let udp = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
        udp.bind_device(Some(tun.as_bytes()))?;
        udp.set_only_v6(false)?;
        udp.set_nonblocking(true)?;
        udp.bind(&SocketAddr::from(([0_u16; 8], PORT)).into())?;
        let udp = Arc::new(UdpSocket::from_std(udp.into())?);
        let tcp = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))?;
        tcp.bind_device(Some(tun.as_bytes()))?;
        tcp.set_only_v6(false)?;
        tcp.set_reuse_address(true)?;
        tcp.set_nonblocking(true)?;
        tcp.bind(&SocketAddr::from(([0_u16; 8], PORT)).into())?;
        tcp.listen(64)?;
        let tcp = TcpListener::from_std(tcp.into())?;
        let servers = Arc::new(servers);
        let task = tokio::spawn(async move {
            let slots = Arc::new(Semaphore::new(64));
            let mut jobs = JoinSet::new();
            let mut bytes = vec![0; QUERY_LIMIT + 1];
            loop {
                tokio::select! {
                    result = udp.recv_from(&mut bytes) => {
                        let Ok((n, peer)) = result else { break; };
                        if n > QUERY_LIMIT || jobs.len() >= 128 || !overlay_source(peer.ip()) { continue; }
                        let Ok(permit) = slots.clone().try_acquire_owned() else { continue; };
                        let query = bytes[..n].to_vec(); let udp = udp.clone(); let servers = servers.clone();
                        jobs.spawn(async move {
                            let _permit = permit;
                            if let Ok(reply) = answer(&query, &servers, false).await { let _ = udp.send_to(&reply, peer).await; }
                        });
                    }
                    result = tcp.accept() => {
                        let Ok((stream, peer)) = result else { break; };
                        if jobs.len() >= 128 || !overlay_source(peer.ip()) { continue; }
                        let Ok(permit) = slots.clone().try_acquire_owned() else { continue; };
                        let servers = servers.clone();
                        jobs.spawn(async move {
                            let _permit = permit;
                            let _ = tokio::time::timeout(Duration::from_secs(30), serve_tcp(stream, &servers)).await;
                        });
                    }
                    _ = jobs.join_next(), if !jobs.is_empty() => {}
                }
            }
        });
        Ok(Self { task })
    }
    pub fn running(&self) -> bool {
        !self.task.is_finished()
    }
}
impl Drop for Forwarder {
    fn drop(&mut self) {
        self.task.abort();
    }
}
fn overlay_source(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.octets()[0] == 33,
        IpAddr::V6(ip) => {
            ip.to_ipv4_mapped().is_some_and(|a| a.octets()[0] == 33) || ip.segments()[0] == 0xfd33
        }
    }
}
async fn serve_tcp(mut stream: TcpStream, servers: &[SocketAddr]) -> Result<()> {
    for _ in 0..128 {
        let size = tokio::time::timeout(TIMEOUT, stream.read_u16()).await?? as usize;
        ensure!((12..=QUERY_LIMIT).contains(&size), "DNS query size");
        let mut query = vec![0; size];
        tokio::time::timeout(TIMEOUT, stream.read_exact(&mut query)).await??;
        let reply = answer(&query, servers, true).await?;
        tokio::time::timeout(TIMEOUT, async {
            stream.write_u16(reply.len() as u16).await?;
            stream.write_all(&reply).await
        })
        .await??;
    }
    Ok(())
}
fn parse_query(bytes: &[u8]) -> Result<Message> {
    ensure!((12..=QUERY_LIMIT).contains(&bytes.len()), "DNS query size");
    let query = Message::from_vec(bytes)?;
    ensure!(
        query.metadata.message_type == MessageType::Query
            && query.metadata.op_code == OpCode::Query
            && query.queries.len() == 1
            && query.signature.is_none(),
        "DNS forwarding accepts one unsigned standard question"
    );
    Ok(query)
}
fn validate_reply(query: &Message, bytes: &[u8]) -> Result<Message> {
    let reply = Message::from_vec(bytes)?;
    ensure!(
        reply.metadata.message_type == MessageType::Response
            && reply.metadata.op_code == query.metadata.op_code
            && reply.metadata.id == query.metadata.id
            && reply.queries == query.queries,
        "DNS response binding"
    );
    Ok(reply)
}
async fn exchange(query: &Message, server: SocketAddr, tcp: bool) -> Result<Message> {
    let runtime = MarkedRuntime::new(Some(super::kernel::MARK));
    let bytes = query.to_vec()?;
    if tcp {
        let mut stream = runtime.tcp(server, None, TIMEOUT).await?;
        stream.write_u16(bytes.len() as u16).await?;
        stream.write_all(&bytes).await?;
        let size = stream.read_u16().await? as usize;
        ensure!(size >= 12, "DNS response length");
        let mut reply = vec![0; size];
        stream.read_exact(&mut reply).await?;
        return validate_reply(query, &reply);
    }
    let bind = if server.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    }
    .parse()?;
    let socket = runtime.udp(bind)?;
    socket.connect(server).await?;
    socket.send(&bytes).await?;
    let mut reply = vec![0; 65_535];
    // Connected socket checks the upstream address; wrong IDs/questions are not
    // accepted as answers. The enclosing timeout also bounds forged input work.
    for _ in 0..8 {
        let n = socket.recv(&mut reply).await?;
        if let Ok(response) = validate_reply(query, &reply[..n]) {
            return Ok(response);
        }
    }
    anyhow::bail!("DNS response mismatch budget")
}
async fn answer(bytes: &[u8], servers: &[SocketAddr], tcp: bool) -> Result<Vec<u8>> {
    let mut query = parse_query(bytes)?;
    let original_id = query.metadata.id;
    let udp_limit = usize::from(query.max_payload()).clamp(512, 1232);
    query.metadata.id = (crate::transport::wire::random_id()? & 0xffff) as u16;
    if let Some(edns) = &mut query.edns {
        edns.set_max_payload(1232);
    }
    let request = async {
        for server in servers {
            if let Ok(Ok(reply)) =
                tokio::time::timeout(Duration::from_secs(1), exchange(&query, *server, tcp)).await
            {
                if !reply.metadata.truncation || tcp {
                    return Ok(reply);
                }
                if let Ok(Ok(reply)) =
                    tokio::time::timeout(Duration::from_secs(1), exchange(&query, *server, true))
                        .await
                {
                    return Ok(reply);
                }
            }
        }
        anyhow::bail!("DNS upstream unavailable")
    };
    let mut reply = match tokio::time::timeout(TIMEOUT, request).await {
        Ok(Ok(reply)) => reply,
        _ => {
            let mut reply = Message::new(original_id, MessageType::Response, OpCode::Query);
            reply.queries = query.queries.clone();
            reply.metadata.response_code = ResponseCode::ServFail;
            reply.metadata.recursion_available = true;
            reply.metadata.recursion_desired = query.metadata.recursion_desired;
            reply
        }
    };
    reply.metadata.id = original_id;
    let bytes = reply.to_vec()?;
    if tcp || bytes.len() <= udp_limit {
        return Ok(bytes);
    }
    // Let the application retry TCP; never fragment a large UDP DNS response.
    reply.answers.clear();
    reply.authorities.clear();
    reply.additionals.clear();
    reply.metadata.truncation = true;
    reply.to_vec().map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_resolver::proto::{
        op::Query,
        rr::{Name, RecordType},
    };
    #[test]
    fn dns_binding_and_query_bounds() {
        let mut query = Message::query();
        query.queries.push(Query::query(
            Name::from_ascii("example.test.").unwrap(),
            RecordType::A,
        ));
        let bytes = query.to_vec().unwrap();
        assert!(parse_query(&bytes).is_ok());
        assert!(parse_query(&vec![0; QUERY_LIMIT + 1]).is_err());
        let mut reply = query.clone().into_response();
        assert!(validate_reply(&query, &reply.to_vec().unwrap()).is_ok());
        reply.metadata.id ^= 1;
        assert!(validate_reply(&query, &reply.to_vec().unwrap()).is_err());
        reply.metadata.id = query.metadata.id;
        reply.queries.clear();
        assert!(validate_reply(&query, &reply.to_vec().unwrap()).is_err());
        query.queries.clear();
        assert!(parse_query(&query.to_vec().unwrap()).is_err());
    }
}
