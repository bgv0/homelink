use std::sync::atomic::{AtomicU64, Ordering};

use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

/// Byte counters shared with the UI.
#[derive(Debug, Default)]
pub struct Traffic {
    /// Bytes sent from the client side towards the internet.
    pub up: AtomicU64,
    /// Bytes received from the internet towards the client side.
    pub down: AtomicU64,
}

/// Copy bytes both ways between a QUIC stream and a TCP socket until both
/// directions finish. `quic_is_client_side` says which direction counts as "up".
pub(crate) async fn splice(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    tcp: TcpStream,
    traffic: &Traffic,
    quic_is_client_side: bool,
) {
    let _ = tcp.set_nodelay(true);
    let (mut tcp_r, mut tcp_w) = tcp.into_split();
    let quic_to_tcp = async {
        let n = tokio::io::copy(&mut recv, &mut tcp_w).await.unwrap_or(0);
        let _ = tcp_w.shutdown().await;
        n
    };
    let tcp_to_quic = async {
        let n = tokio::io::copy(&mut tcp_r, &mut send).await.unwrap_or(0);
        let _ = send.finish();
        n
    };
    let (a, b) = tokio::join!(quic_to_tcp, tcp_to_quic);
    let (up, down) = if quic_is_client_side { (a, b) } else { (b, a) };
    traffic.up.fetch_add(up, Ordering::Relaxed);
    traffic.down.fetch_add(down, Ordering::Relaxed);
}
