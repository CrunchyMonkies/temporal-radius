//! Minimal HTTP health endpoint for Docker `HEALTHCHECK` and Kubernetes probes.
//!
//! Hand-rolled on std/tokio (already linked) instead of an HTTP server crate to keep the binary
//! small. Only the request line is read; every response closes the connection.
//!
//! - `GET /healthz` — liveness: 200 whenever the runtime can answer.
//! - `GET /readyz`  — readiness: 200 while the last successful dependency check is fresh, else 503.

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

const IO_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_REQUEST_LINE: usize = 1024;

/// Shared readiness state. `last_ok` is the monotonic time (ms since `epoch`, +1 so that 0 means
/// "never") of the last successful check; monotonic so wall-clock steps can't flip readiness.
#[derive(Clone)]
pub struct Health {
    epoch: Instant,
    last_ok: Arc<AtomicU64>,
    stale_after: Duration,
}

impl Health {
    /// Readiness lapses if no successful check has been recorded within `stale_after`.
    pub fn new(stale_after: Duration) -> Self {
        Self { epoch: Instant::now(), last_ok: Arc::new(AtomicU64::new(0)), stale_after }
    }

    pub fn set_ready(&self, ready: bool) {
        self.last_ok.store(if ready { self.now_ms() + 1 } else { 0 }, Ordering::Relaxed);
    }

    pub fn is_ready(&self) -> bool {
        let last = self.last_ok.load(Ordering::Relaxed);
        let stale_ms = u64::try_from(self.stale_after.as_millis()).unwrap_or(u64::MAX);
        last != 0 && (self.now_ms() + 1).saturating_sub(last) <= stale_ms
    }

    fn now_ms(&self) -> u64 {
        self.epoch.elapsed().as_millis() as u64
    }
}

/// Binds `addr` and serves health requests until the process exits.
pub async fn spawn(addr: SocketAddr, health: Health) -> std::io::Result<SocketAddr> {
    let listener = TcpListener::bind(addr).await?;
    let local = listener.local_addr()?;
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    tokio::spawn(handle(stream, health.clone()));
                }
                Err(e) => tracing::warn!("health accept failed: {e}"),
            }
        }
    });
    Ok(local)
}

async fn handle(mut stream: tokio::net::TcpStream, health: Health) {
    let mut buf = [0u8; MAX_REQUEST_LINE];
    let mut len = 0;
    // Read until the end of the request line (or the cap / timeout).
    let read = tokio::time::timeout(IO_TIMEOUT, async {
        while len < buf.len() {
            let n = stream.read(&mut buf[len..]).await?;
            if n == 0 {
                break;
            }
            len += n;
            if buf[..len].contains(&b'\n') {
                break;
            }
        }
        Ok::<_, std::io::Error>(())
    })
    .await;
    if !matches!(read, Ok(Ok(()))) {
        return;
    }
    let line = std::str::from_utf8(&buf[..len]).unwrap_or("");
    let mut parts = line.split_ascii_whitespace();
    let (status, body) = match (parts.next(), parts.next()) {
        (Some("GET" | "HEAD"), Some("/healthz")) => ("200 OK", "ok\n"),
        (Some("GET" | "HEAD"), Some("/readyz")) if health.is_ready() => ("200 OK", "ready\n"),
        (Some("GET" | "HEAD"), Some("/readyz")) => ("503 Service Unavailable", "not ready\n"),
        _ => ("404 Not Found", "not found\n"),
    };
    let resp = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = tokio::time::timeout(IO_TIMEOUT, stream.write_all(resp.as_bytes())).await;
}

/// Blocking client used by the `healthcheck` subcommand: true if `path` answers 200.
pub fn probe(addr: SocketAddr, path: &str) -> bool {
    let run = || -> std::io::Result<bool> {
        let mut s = TcpStream::connect_timeout(&addr, IO_TIMEOUT)?;
        s.set_read_timeout(Some(IO_TIMEOUT))?;
        s.set_write_timeout(Some(IO_TIMEOUT))?;
        s.write_all(format!("GET {path} HTTP/1.0\r\n\r\n").as_bytes())?;
        let mut head = [0u8; 32];
        let n = s.read(&mut head)?;
        Ok(head[..n].starts_with(b"HTTP/1.1 200 "))
    };
    run().unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn start(health: &Health) -> SocketAddr {
        spawn("127.0.0.1:0".parse().unwrap(), health.clone()).await.unwrap()
    }

    // `probe` is blocking; run it off the async runtime.
    async fn probe_async(addr: SocketAddr, path: &'static str) -> bool {
        tokio::task::spawn_blocking(move || probe(addr, path)).await.unwrap()
    }

    async fn status(addr: SocketAddr, path: &'static str) -> String {
        tokio::task::spawn_blocking(move || {
            let mut s = TcpStream::connect(addr).unwrap();
            s.write_all(format!("GET {path} HTTP/1.0\r\n\r\n").as_bytes()).unwrap();
            let mut out = String::new();
            s.read_to_string(&mut out).unwrap();
            out.lines().next().unwrap_or_default().to_string()
        })
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn liveness_and_readiness() {
        let health = Health::new(Duration::from_secs(30));
        let addr = start(&health).await;

        assert_eq!(status(addr, "/healthz").await, "HTTP/1.1 200 OK");
        assert_eq!(status(addr, "/readyz").await, "HTTP/1.1 503 Service Unavailable");
        assert!(probe_async(addr, "/healthz").await);
        assert!(!probe_async(addr, "/readyz").await);

        health.set_ready(true);
        assert_eq!(status(addr, "/readyz").await, "HTTP/1.1 200 OK");
        assert!(probe_async(addr, "/readyz").await);

        health.set_ready(false);
        assert!(!probe_async(addr, "/readyz").await);
        assert_eq!(status(addr, "/nope").await, "HTTP/1.1 404 Not Found");
    }

    #[tokio::test]
    async fn readiness_goes_stale() {
        let health = Health::new(Duration::from_millis(100));
        health.set_ready(true);
        assert!(health.is_ready());
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(!health.is_ready());
        health.set_ready(true);
        assert!(health.is_ready());
        // Duration::MAX (used by the responder) never goes stale.
        let forever = Health::new(Duration::MAX);
        forever.set_ready(true);
        assert!(forever.is_ready());
    }

    #[tokio::test]
    async fn probe_fails_when_nothing_listens() {
        let addr = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap()
        };
        assert!(!probe_async(addr, "/healthz").await);
    }

    #[tokio::test]
    async fn idle_client_is_dropped() {
        let addr = start(&Health::new(Duration::from_secs(30))).await;
        let closed = tokio::task::spawn_blocking(move || {
            let mut s = TcpStream::connect(addr).unwrap();
            s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut b = [0u8; 1];
            // Server gives up after IO_TIMEOUT without a request line and closes the socket.
            matches!(s.read(&mut b), Ok(0))
        })
        .await
        .unwrap();
        assert!(closed);
    }
}
