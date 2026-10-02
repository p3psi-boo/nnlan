//! One dormant high-resolution wakeup for queued, paced data. Tokio's ordinary
//! millisecond maintenance timer remains responsible for control/liveness.
use nix::sys::{
    time::TimeSpec,
    timerfd::{ClockId, Expiration, TimerFd, TimerFlags, TimerSetTimeFlags},
};
use std::{
    io,
    os::fd::{AsFd, AsRawFd, RawFd},
    time::{Duration, Instant},
};
use tokio::io::unix::AsyncFd;

struct Handle(TimerFd);
impl AsRawFd for Handle {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_fd().as_raw_fd()
    }
}
pub(super) struct PacerWake {
    fd: AsyncFd<Handle>,
    deadline: Option<Instant>,
}
impl PacerWake {
    pub fn new() -> io::Result<Self> {
        Ok(Self {
            fd: AsyncFd::new(Handle(TimerFd::new(
                ClockId::CLOCK_MONOTONIC,
                TimerFlags::TFD_NONBLOCK | TimerFlags::TFD_CLOEXEC,
            )?))?,
            deadline: None,
        })
    }
    pub fn arm(&mut self, deadline: Option<Instant>) -> io::Result<()> {
        if deadline == self.deadline
            || matches!((self.deadline, deadline), (Some(old), Some(new)) if old <= new)
        {
            return Ok(());
        }
        let delay = deadline.map_or(Duration::ZERO, |at| {
            at.saturating_duration_since(Instant::now())
                .max(Duration::from_nanos(1))
        });
        self.fd.get_ref().0.set(
            Expiration::OneShot(TimeSpec::from_duration(delay)),
            TimerSetTimeFlags::empty(),
        )?;
        self.deadline = deadline;
        Ok(())
    }
    pub async fn wait(&mut self) -> io::Result<()> {
        loop {
            let mut ready = self.fd.readable().await?;
            match ready.try_io(|fd| {
                let mut expirations = [0; 8];
                nix::unistd::read(fd.get_ref().0.as_fd(), &mut expirations).map_err(io::Error::from)
            }) {
                Ok(result) => {
                    let n = result?;
                    if n != 8 {
                        return Err(io::Error::other("short pacer timer read"));
                    }
                    self.deadline = None;
                    return Ok(());
                }
                Err(_) => continue,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test(flavor = "current_thread")]
    async fn one_shot_is_not_postponed_by_activity_and_goes_idle() {
        let mut timer = PacerWake::new().unwrap();
        let first = Instant::now() + Duration::from_micros(250);
        timer.arm(Some(first)).unwrap();
        timer.arm(Some(first + Duration::from_secs(1))).unwrap();
        assert_eq!(timer.deadline, Some(first));
        tokio::time::timeout(Duration::from_secs(1), timer.wait())
            .await
            .unwrap()
            .unwrap();
        assert!(timer.deadline.is_none());
        assert!(
            tokio::time::timeout(Duration::from_millis(2), timer.wait())
                .await
                .is_err()
        );
        timer.arm(Some(Instant::now())).unwrap();
        timer.arm(None).unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(2), timer.wait())
                .await
                .is_err()
        );
    }
}
