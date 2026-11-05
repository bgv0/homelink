use std::sync::atomic::{AtomicU64, Ordering};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

/// Live byte counters shared with the UI.
#[derive(Debug, Default)]
pub struct Traffic {
    /// Bytes from the client side towards the internet.
    pub up: AtomicU64,
    /// Bytes from the internet towards the client side.
    pub down: AtomicU64,
}

/// Copy, adding to `counter` as data flows so the UI sees live numbers.
async fn copy_counted<R, W>(r: &mut R, w: &mut W, counter: &AtomicU64)
where
    R: AsyncRead + Unpin + ?Sized,
    W: AsyncWrite + Unpin + ?Sized,
{
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = match r.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        // Flush each chunk: TLS streams buffer writes until flushed.
        if w.write_all(&buf[..n]).await.is_err() || w.flush().await.is_err() {
            break;
        }
        counter.fetch_add(n as u64, Ordering::Relaxed);
    }
}

/// Copy bytes both ways between a tunnel stream (QUIC stream or TLS-over-TCP)
/// and a TCP socket until both directions finish. On the host the TCP side is
/// the internet; on the client it is the local app.
pub(crate) async fn splice<R, W>(mut tun_r: R, mut tun_w: W, tcp: TcpStream, traffic: &Traffic, on_host: bool)
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let _ = tcp.set_nodelay(true);
    let (mut tcp_r, mut tcp_w) = tcp.into_split();
    let (tun_to_tcp, tcp_to_tun) = if on_host {
        (&traffic.up, &traffic.down)
    } else {
        (&traffic.down, &traffic.up)
    };
    let a = async {
        copy_counted(&mut tun_r, &mut tcp_w, tun_to_tcp).await;
        let _ = tcp_w.shutdown().await;
    };
    let b = async {
        copy_counted(&mut tcp_r, &mut tun_w, tcp_to_tun).await;
        // For QUIC this finishes the stream; for TLS it sends close_notify.
        let _ = tun_w.shutdown().await;
    };
    tokio::join!(a, b);
}
