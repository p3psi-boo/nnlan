//! One replaceable desired snapshot, one kernel writer; no queue of stale jobs.
use super::routes::HostRoutes;
use anyhow::{Context, Result, bail, ensure};
use std::{
    collections::BTreeSet,
    net::IpAddr,
    sync::{Arc, Condvar, Mutex},
    thread::{self, JoinHandle},
};

#[derive(Default)]
struct State {
    desired: Arc<BTreeSet<IpAddr>>,
    generation: u64,
    completed: u64,
    stop: bool,
    error: Option<String>,
}
struct Shared {
    state: Mutex<State>,
    wake: Condvar,
}
pub(super) struct RouteWorker {
    shared: Arc<Shared>,
    thread: Option<JoinHandle<()>>,
}
impl RouteWorker {
    pub(super) fn open(name: &str, mtu: u16) -> Result<Self> {
        // Open in the owning network namespace before moving the socket.
        let mut routes = HostRoutes::open(name, mtu)?;
        Self::start(move |address, add| routes.change(address, add))
    }
    fn start(mut change: impl FnMut(IpAddr, bool) -> Result<()> + Send + 'static) -> Result<Self> {
        let shared = Arc::new(Shared {
            state: Mutex::new(State::default()),
            wake: Condvar::new(),
        });
        let writer = Arc::clone(&shared);
        let thread = thread::Builder::new()
            .name("nnlan-routes".into())
            .spawn(move || {
                if let Err(error) = reconcile(&writer, &mut change)
                    && let Ok(mut state) = writer.state.lock()
                {
                    state.error = Some(format!("{error:#}"));
                }
            })?;
        Ok(Self {
            shared,
            thread: Some(thread),
        })
    }
    pub(super) fn replace(&self, desired: BTreeSet<IpAddr>) -> Result<()> {
        ensure!(
            desired.len() <= super::super::control::MAX_NODES * 2,
            "host route capacity"
        );
        self.ready()?;
        let mut state = self
            .shared
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("route worker state poisoned"))?;
        if *state.desired != desired {
            state.generation = state
                .generation
                .checked_add(1)
                .context("route generation exhausted")?;
            state.desired = Arc::new(desired);
            self.shared.wake.notify_one();
        }
        Ok(())
    }
    pub(super) fn ready(&self) -> Result<bool> {
        let state = self
            .shared
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("route worker state poisoned"))?;
        if let Some(error) = &state.error {
            bail!("TUN route worker: {error}");
        }
        ensure!(
            self.thread.as_ref().is_some_and(|t| !t.is_finished()),
            "TUN route worker stopped"
        );
        Ok(state.completed == state.generation)
    }
}
impl Drop for RouteWorker {
    fn drop(&mut self) {
        // Join before dropping TUN, including when a kernel ACK is in flight.
        if let Ok(mut state) = self.shared.state.lock() {
            state.stop = true;
            self.shared.wake.notify_one();
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
fn reconcile(shared: &Shared, change: &mut impl FnMut(IpAddr, bool) -> Result<()>) -> Result<()> {
    let mut installed = BTreeSet::new();
    loop {
        let (generation, desired) = {
            let state = shared
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("route worker state poisoned"))?;
            let state = shared
                .wake
                .wait_while(state, |s| !s.stop && s.generation == s.completed)
                .map_err(|_| anyhow::anyhow!("route worker state poisoned"))?;
            if state.stop {
                return Ok(());
            }
            (state.generation, Arc::clone(&state.desired))
        };
        // Removal first. A superseded in-flight add is recorded after its ACK,
        // then removed by the next snapshot; never pretend it did not happen.
        let changes: Vec<_> = installed
            .difference(&desired)
            .map(|&a| (a, false))
            .chain(desired.difference(&installed).map(|&a| (a, true)))
            .collect();
        let mut superseded = false;
        for (address, add) in changes {
            {
                let state = shared
                    .state
                    .lock()
                    .map_err(|_| anyhow::anyhow!("route worker state poisoned"))?;
                if state.stop {
                    return Ok(());
                }
                if state.generation != generation {
                    superseded = true;
                    break;
                }
            }
            change(address, add)?;
            if add {
                installed.insert(address);
            } else {
                installed.remove(&address);
            }
        }
        let mut state = shared
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("route worker state poisoned"))?;
        if !superseded && state.generation == generation {
            state.completed = generation;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::mpsc,
        time::{Duration, Instant},
    };

    fn ip(n: u8) -> IpAddr {
        std::net::Ipv4Addr::new(33, 0, 0, n).into()
    }
    fn wait_ready(worker: &RouteWorker) {
        let until = Instant::now() + Duration::from_secs(3);
        while !worker.ready().unwrap() {
            assert!(Instant::now() < until);
            thread::sleep(Duration::from_millis(1));
        }
    }
    #[test]
    fn blocked_kernel_does_not_block_owner_and_superseded_snapshots_coalesce() {
        let (started, receiving) = mpsc::channel();
        let (release, blocked) = mpsc::channel();
        let operations = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&operations);
        let mut first = true;
        let worker = RouteWorker::start(move |a, add| {
            if first {
                first = false;
                started.send(()).unwrap();
                blocked.recv_timeout(Duration::from_secs(3)).unwrap();
            }
            log.lock().unwrap().push((a, add));
            Ok(())
        })
        .unwrap();
        worker.replace(BTreeSet::from([ip(1), ip(2)])).unwrap();
        receiving.recv_timeout(Duration::from_secs(3)).unwrap();
        assert!(!worker.ready().unwrap());
        for n in 3..=100 {
            worker.replace(BTreeSet::from([ip(n)])).unwrap();
        }
        assert!(
            !worker.ready().unwrap(),
            "old ACK must not mark the new generation ready"
        );
        release.send(()).unwrap();
        wait_ready(&worker);
        assert_eq!(
            *operations.lock().unwrap(),
            [(ip(1), true), (ip(1), false), (ip(100), true)]
        );
        worker.replace(BTreeSet::from([ip(100)])).unwrap();
        assert!(
            worker.ready().unwrap(),
            "identical desired state does not cause another job"
        );
        worker.replace(BTreeSet::new()).unwrap();
        wait_ready(&worker);
        assert_eq!(operations.lock().unwrap().last(), Some(&(ip(100), false)));
    }
    #[test]
    fn kernel_errors_are_fatal_not_successful_completion() {
        let worker = RouteWorker::start(|_, _| bail!("simulated exclusive-add conflict")).unwrap();
        worker.replace(BTreeSet::from([ip(1)])).unwrap();
        let until = Instant::now() + Duration::from_secs(3);
        loop {
            if let Err(error) = worker.ready() {
                assert!(
                    error
                        .to_string()
                        .contains("simulated exclusive-add conflict")
                );
                break;
            }
            assert!(Instant::now() < until);
            thread::sleep(Duration::from_millis(1));
        }
        assert!(worker.replace(BTreeSet::new()).is_err());
    }
    #[test]
    fn shutdown_joins_the_in_flight_writer() {
        let (started, receiving) = mpsc::channel();
        let (release, blocked) = mpsc::channel();
        let worker = RouteWorker::start(move |_, _| {
            started.send(()).unwrap();
            blocked.recv_timeout(Duration::from_secs(3)).unwrap();
            Ok(())
        })
        .unwrap();
        worker.replace(BTreeSet::from([ip(1), ip(2)])).unwrap();
        receiving.recv_timeout(Duration::from_secs(3)).unwrap();
        let (done, finished) = mpsc::channel();
        let shared = Arc::clone(&worker.shared);
        let owner = thread::spawn(move || {
            drop(worker);
            done.send(()).unwrap();
        });
        let until = Instant::now() + Duration::from_secs(3);
        while !shared.state.lock().unwrap().stop {
            assert!(Instant::now() < until);
            thread::yield_now();
        }
        assert!(finished.try_recv().is_err());
        release.send(()).unwrap();
        finished.recv_timeout(Duration::from_secs(3)).unwrap();
        owner.join().unwrap();
        assert!(
            receiving.try_recv().is_err(),
            "shutdown performs no second operation"
        );
    }
}
