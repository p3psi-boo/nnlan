//! DNS for configured peer hostnames only. Marked sockets never serve app queries.
use crate::{config::Config, identity::NodeId};
use anyhow::{Context, Result, ensure};
use hickory_resolver::{
    Resolver,
    config::{NameServerConfig, ResolverConfig},
    net::runtime::{RuntimeProvider, TokioRuntimeProvider},
};
use socket2::{Domain, Protocol, SockRef, Socket, Type};
use std::{future::Future, io, net::SocketAddr, pin::Pin, sync::Arc, time::Duration};
use tokio::{
    net::{TcpSocket, UdpSocket},
    sync::mpsc,
};

#[derive(Clone, Default)]
pub(super) struct MarkedRuntime {
    mark: Option<u32>,
    inner: TokioRuntimeProvider,
}
impl MarkedRuntime {
    pub fn new(mark: Option<u32>) -> Self {
        Self {
            mark,
            inner: TokioRuntimeProvider::default(),
        }
    }
    pub fn udp(&self, address: SocketAddr) -> io::Result<UdpSocket> {
        let socket = Socket::new(
            Domain::for_address(address),
            Type::DGRAM,
            Some(Protocol::UDP),
        )?;
        if let Some(mark) = self.mark {
            socket.set_mark(mark)?;
        }
        socket.set_nonblocking(true)?;
        socket.bind(&address.into())?;
        UdpSocket::from_std(socket.into())
    }
    pub async fn tcp(
        &self,
        server: SocketAddr,
        bind: Option<SocketAddr>,
        timeout: Duration,
    ) -> io::Result<tokio::net::TcpStream> {
        let socket = if server.is_ipv4() {
            TcpSocket::new_v4()?
        } else {
            TcpSocket::new_v6()?
        };
        if let Some(mark) = self.mark {
            SockRef::from(&socket).set_mark(mark)?;
        }
        if let Some(bind) = bind {
            socket.bind(bind)?;
        }
        tokio::time::timeout(timeout, socket.connect(server)).await?
    }
}
impl RuntimeProvider for MarkedRuntime {
    type Handle = <TokioRuntimeProvider as RuntimeProvider>::Handle;
    type Timer = <TokioRuntimeProvider as RuntimeProvider>::Timer;
    type Udp = UdpSocket;
    type Tcp = <TokioRuntimeProvider as RuntimeProvider>::Tcp;
    fn create_handle(&self) -> Self::Handle {
        self.inner.create_handle()
    }
    fn bind_udp(
        &self,
        local: SocketAddr,
        _server: SocketAddr,
    ) -> Pin<Box<dyn Send + Future<Output = io::Result<Self::Udp>>>> {
        let result = self.udp(local);
        Box::pin(async move { result })
    }
    fn connect_tcp(
        &self,
        server: SocketAddr,
        bind: Option<SocketAddr>,
        timeout: Option<Duration>,
    ) -> Pin<Box<dyn Send + Future<Output = io::Result<Self::Tcp>>>> {
        let runtime = self.clone();
        Box::pin(async move {
            Ok(hickory_resolver::net::runtime::iocompat::AsyncIoTokioAsStd(
                runtime
                    .tcp(server, bind, timeout.unwrap_or(Duration::from_secs(3)))
                    .await?,
            ))
        })
    }
}

pub(super) fn servers(config: &Config, bootstrap: bool) -> Result<Vec<SocketAddr>> {
    if !config.dns_servers.is_empty() {
        ensure!(
            !bootstrap || config.dns_servers.iter().all(|s| !s.ip().is_loopback()),
            "marked peer DNS needs actual upstream dns_servers, not a loopback stub"
        );
        return Ok(config.dns_servers.clone());
    }
    let (mut system, _) = hickory_resolver::system_conf::read_system_conf()?;
    if bootstrap && system.name_servers().iter().all(|s| s.ip.is_loopback()) {
        // systemd-resolved's stub cannot bootstrap an exit through its own blocked
        // outbound sockets. Use its actual upstreams, never an arbitrary public DNS.
        if let Ok(bytes) = std::fs::read("/run/systemd/resolve/resolv.conf") {
            system = hickory_resolver::system_conf::parse_resolv_conf(&bytes)?.0;
        }
    }
    let result: Vec<_> = system
        .name_servers()
        .iter()
        .filter(|s| !bootstrap || !s.ip.is_loopback())
        .take(8)
        .map(|s| SocketAddr::new(s.ip, 53))
        .collect();
    ensure!(
        !result.is_empty(),
        "set dns_servers to actual upstream IP:port addresses for marked peer DNS; a loopback stub cannot bootstrap an exit"
    );
    Ok(result)
}

pub(super) fn build(config: &Config) -> Result<Option<Arc<Resolver<MarkedRuntime>>>> {
    if config
        .peers
        .iter()
        .all(|p| p.endpoint.parse::<SocketAddr>().is_ok())
    {
        return Ok(None);
    }
    let servers = servers(config, config.tun.enabled)?;
    let nameservers = servers
        .into_iter()
        .map(|server| {
            let mut ns = NameServerConfig::udp_and_tcp(server.ip());
            for connection in &mut ns.connections {
                connection.port = server.port();
            }
            ns
        })
        .collect::<Vec<_>>();
    let mut builder = Resolver::builder_with_config(
        ResolverConfig::from_parts(None, vec![], nameservers),
        MarkedRuntime::new(config.tun.enabled.then_some(super::kernel::MARK)),
    );
    builder.options_mut().timeout = Duration::from_secs(2);
    builder.options_mut().attempts = 2;
    builder.options_mut().cache_size = 256;
    Ok(Some(Arc::new(builder.build()?)))
}

pub(super) async fn run(
    config: Config,
    resolver: Option<Arc<Resolver<MarkedRuntime>>>,
    tx: mpsc::Sender<(NodeId, Vec<SocketAddr>)>,
) {
    loop {
        let mut jobs = tokio::task::JoinSet::new();
        for peer in &config.peers {
            let peer = peer.clone();
            let resolver = resolver.clone();
            let ipv6 = config.listen.is_ipv6();
            jobs.spawn(async move {
                let query = async {
                    if let Ok(address) = peer.endpoint.parse::<SocketAddr>() {
                        return Ok(vec![address]);
                    }
                    let (host, port) = peer.endpoint.rsplit_once(':').context("peer endpoint")?;
                    let resolver = resolver.context("peer resolver")?;
                    let addresses = resolver.lookup_ip(format!("{host}.")).await?;
                    let port = port.parse()?;
                    Ok::<_, anyhow::Error>(
                        addresses
                            .iter()
                            .map(|ip| SocketAddr::new(ip, port))
                            .collect::<Vec<_>>(),
                    )
                };
                let addresses = match tokio::time::timeout(Duration::from_secs(4), query).await {
                    Ok(Ok(addresses)) => addresses
                        .into_iter()
                        .filter(|a| ipv6 || a.is_ipv4())
                        .take(8)
                        .collect(),
                    _ => vec![],
                };
                (peer.public_key, addresses)
            });
        }
        while let Some(Ok(result)) = jobs.join_next().await {
            if !result.1.is_empty() && tx.send(result).await.is_err() {
                return;
            }
        }
        tokio::time::sleep(Duration::from_secs(30)).await;
    }
}
