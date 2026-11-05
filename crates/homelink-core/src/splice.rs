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
        if w.write_all(&buf[..n]).await.is_err() {
            break;
        }
        counter.fetch_add(n as u64, Ordering::Relaxed);
    }
}

/// Copy bytes both ways between a QUIC stream and a TCP socket until both
/// directions finish. On the host the TCP side is the internet; on the client
/// it is the local app.
pub(crate) async fn splice(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    tcp: TcpStream,
    traffic: &Traffic,
    on_host: bool,
) {
    let _ = tcp.set_nodelay(true);
    let (mut tcp_r, mut tcp_w) = tcp.into_split();
    let (quic_to_tcp, tcp_to_quic) = if on_host {
        (&traffic.up, &traffic.down)
    } else {
        (&traffic.down, &traffic.up)
    };
    let a = async {
        copy_counted(&mut recv, &mut tcp_w, quic_to_tcp).await;
        let _ = tcp_w.shutdown().await;
    };
    let b = async {
        copy_counted(&mut tcp_r, &mut send, tcp_to_quic).await;
        let _ = send.finish();
    };
    tokio::join!(a, b);
}
