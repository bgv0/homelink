//! Host and client in one process over loopback. Offline: no internet needed.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use homelink_core::client::{self, Client, ClientError};
use homelink_core::host::{self, HostHandle, HostOptions};
use homelink_core::proto::{Invite, Status, Target};
use homelink_core::socks;
use homelink_core::store::Store;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

struct Env {
    _dirs: (tempfile::TempDir, tempfile::TempDir),
    host_store: Store,
    client_store: Store,
    host: HostHandle,
}

async fn setup(allow_lan: bool) -> Env {
    let hd = tempfile::tempdir().unwrap();
    let cd = tempfile::tempdir().unwrap();
    let host_store = Store::open(hd.path()).unwrap();
    let client_store = Store::open(cd.path()).unwrap();
    let opts = HostOptions {
        bind: "127.0.0.1:0".parse().unwrap(),
        allow_lan,
        require_approval: true,
        blocked: vec![],
        revoke_poll: Duration::from_millis(200),
    };
    let host = host::start(host_store.clone(), opts, host::auto_approve()).await.unwrap();
    Env { _dirs: (hd, cd), host_store, client_store, host }
}

impl Env {
    fn invite(&self, ttl: u64) -> Invite {
        let id = self.host_store.identity().unwrap().id;
        self.host_store
            .create_invite(id, "127.0.0.1".into(), self.host.local_addr.port(), ttl)
            .unwrap()
    }

    async fn paired_client(&self) -> Client {
        let identity = self.client_store.identity().unwrap();
        let saved = client::pair(&identity, &self.invite(600), "test laptop", Some("home"))
            .await
            .unwrap();
        Client::new(&identity, saved).unwrap()
    }
}

async fn echo_server() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    addr
}

#[tokio::test]
async fn pair_then_proxy_through_socks() {
    let env = setup(true).await;
    let client = Arc::new(env.paired_client().await);
    assert_eq!(env.host_store.devices().unwrap().len(), 1);
    assert_eq!(env.host_store.devices().unwrap()[0].name, "test laptop");
    assert!(env.host_store.invites().unwrap().is_empty(), "invite is single-use");

    let echo = echo_server().await;
    let socks_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socks_addr = socks_listener.local_addr().unwrap();
    tokio::spawn(socks::serve(client.clone(), socks_listener));

    // SOCKS5 CONNECT by domain name ("localhost") to the echo server.
    let mut s = TcpStream::connect(socks_addr).await.unwrap();
    s.write_all(&[5, 1, 0]).await.unwrap();
    let mut b2 = [0u8; 2];
    s.read_exact(&mut b2).await.unwrap();
    assert_eq!(b2, [5, 0]);
    let mut req = vec![5, 1, 0, 3, 9];
    req.extend_from_slice(b"localhost");
    req.extend_from_slice(&echo.port().to_be_bytes());
    s.write_all(&req).await.unwrap();
    let mut rep = [0u8; 10];
    s.read_exact(&mut rep).await.unwrap();
    assert_eq!(rep[1], 0, "socks reply ok");

    let payload: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    let (mut r, mut w) = s.into_split();
    let p = payload.clone();
    let writer = tokio::spawn(async move {
        w.write_all(&p).await.unwrap();
        w.shutdown().await.unwrap();
    });
    let mut got = Vec::new();
    r.read_to_end(&mut got).await.unwrap();
    writer.await.unwrap();
    assert_eq!(got, payload);
    assert!(client.rtt().await.is_some());

    // Counters: echo means the same bytes went up and came back down.
    use std::sync::atomic::Ordering::Relaxed;
    let n = payload.len() as u64;
    assert_eq!(client.traffic.up.load(Relaxed), n);
    assert_eq!(client.traffic.down.load(Relaxed), n);
    assert_eq!(env.host.traffic.up.load(Relaxed), n);
    assert_eq!(env.host.traffic.down.load(Relaxed), n);
}

#[tokio::test]
async fn local_network_blocked_by_default() {
    let env = setup(false).await;
    let client = env.paired_client().await;
    let echo = echo_server().await;
    for target in [Target::Addr(echo), Target::Domain("localhost".into(), echo.port())] {
        match client.open(&target).await {
            Err(ClientError::Status(Status::Blocked)) => {}
            other => panic!("expected Blocked for {target}, got {:?}", other.map(|_| ())),
        }
    }
}

#[tokio::test]
async fn unpaired_device_is_refused() {
    let env = setup(true).await;
    let stranger_dir = tempfile::tempdir().unwrap();
    let stranger = Store::open(stranger_dir.path()).unwrap();
    let saved = homelink_core::store::SavedHost {
        name: "home".into(),
        addr: "127.0.0.1".into(),
        port: env.host.local_addr.port(),
        id: homelink_core::proto::id_hex(&env.host_store.identity().unwrap().id),
    };
    let client = Client::new(&stranger.identity().unwrap(), saved).unwrap();
    let echo = echo_server().await;
    match client.open(&Target::Addr(echo)).await {
        Err(ClientError::NotPaired) => {}
        other => panic!("expected NotPaired, got {:?}", other.map(|_| ())),
    }
}

#[tokio::test]
async fn bad_invites_rejected() {
    let env = setup(true).await;
    let identity = env.client_store.identity().unwrap();

    let mut wrong = env.invite(600);
    wrong.secret = [0x55; 32];
    match client::pair(&identity, &wrong, "x", None).await {
        Err(ClientError::Status(Status::Denied)) => {}
        other => panic!("expected Denied, got {other:?}"),
    }

    let mut expired = env.invite(600);
    expired.expires = 1;
    assert!(matches!(
        client::pair(&identity, &expired, "x", None).await,
        Err(ClientError::Status(Status::Expired))
    ));

    // Pinned host key: an invite naming a different host id must fail.
    let mut impostor = env.invite(600);
    impostor.host_id = [0xaa; 32];
    assert!(client::pair(&identity, &impostor, "x", None).await.is_err());
    assert!(env.host_store.devices().unwrap().is_empty());
}

#[tokio::test]
async fn revoked_device_is_disconnected() {
    let env = setup(true).await;
    let client = env.paired_client().await;
    let echo = echo_server().await;
    let (mut send, mut recv) = client.open(&Target::Addr(echo)).await.unwrap();
    send.write_all(b"hi").await.unwrap();
    let mut b = [0u8; 2];
    recv.read_exact(&mut b).await.unwrap();

    let id = env.host_store.devices().unwrap()[0].id.clone();
    env.host_store.revoke(&id[..8]).unwrap();
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert!(env.host.online().is_empty());
    match client.open(&Target::Addr(echo)).await {
        Err(ClientError::NotPaired) => {}
        other => panic!("expected NotPaired after revoke, got {:?}", other.map(|_| ())),
    }
}

#[tokio::test]
async fn unreachable_host_times_out_quickly() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let saved = homelink_core::store::SavedHost {
        name: "nobody".into(),
        addr: "127.0.0.1".into(),
        port: 9, // nothing listening
        id: "00".repeat(32),
    };
    let client = Client::new(&store.identity().unwrap(), saved).unwrap();
    let start = std::time::Instant::now();
    let r = client.open(&Target::Domain("example.com".into(), 80)).await;
    assert!(r.is_err());
    assert!(start.elapsed() < Duration::from_secs(12));
}

#[tokio::test]
async fn known_device_can_reuse_new_invite_to_update_address() {
    let env = setup(true).await;
    let _ = env.paired_client().await;
    let identity = env.client_store.identity().unwrap();
    let again = client::pair(&identity, &env.invite(600), "test laptop", Some("home"))
        .await
        .unwrap();
    assert_eq!(again.port, env.host.local_addr.port());
    assert_eq!(env.host_store.devices().unwrap().len(), 1, "no duplicate device");

    env.client_store.save_host(again.clone()).unwrap();
    env.client_store.update_host_address("home", "localhost", 4000).unwrap();
    let h = env.client_store.find_host(Some("home")).unwrap();
    assert_eq!((h.addr.as_str(), h.port), ("localhost", 4000));
    assert!(env.client_store.update_host_address("home", "bad host!", 1).is_err());
}

// ---------------------------------------------------------------------------
// TLS-over-TCP fallback
// ---------------------------------------------------------------------------

async fn tcp_client(env: &Env) -> Client {
    let identity = env.client_store.identity().unwrap();
    let saved = client::pair_tcp(&identity, &env.invite(600), "tcp laptop", Some("home"))
        .await
        .unwrap();
    Client::new(&identity, saved).unwrap().with_tcp_only()
}

async fn echo_roundtrip(client: &Client, echo: SocketAddr, n: usize) {
    let (mut w, mut r) = client.open(&Target::Addr(echo)).await.unwrap();
    let payload: Vec<u8> = (0..n).map(|i| (i % 253) as u8).collect();
    let p = payload.clone();
    let writer = tokio::spawn(async move {
        w.write_all(&p).await.unwrap();
        w.flush().await.unwrap();
        w.shutdown().await.unwrap();
    });
    let mut got = Vec::new();
    r.read_to_end(&mut got).await.unwrap();
    writer.await.unwrap();
    assert_eq!(got, payload);
}

#[tokio::test]
async fn tcp_pair_and_proxy() {
    let env = setup(true).await;
    assert!(env.host.tcp_enabled);
    let client = tcp_client(&env).await;
    assert_eq!(env.host_store.devices().unwrap().len(), 1);
    let echo = echo_server().await;
    echo_roundtrip(&client, echo, 300_000).await;
    assert_eq!(client.transport(), client::Transport::Tcp);
    use std::sync::atomic::Ordering::Relaxed;
    assert_eq!(env.host.traffic.up.load(Relaxed), 300_000);
    assert_eq!(env.host.traffic.down.load(Relaxed), 300_000);
}

#[tokio::test]
async fn tcp_blocks_lan_and_refuses_strangers() {
    let env = setup(false).await;
    let client = tcp_client(&env).await;
    let echo = echo_server().await;
    assert!(matches!(
        client.open(&Target::Addr(echo)).await,
        Err(ClientError::Status(Status::Blocked))
    ));

    let stranger_dir = tempfile::tempdir().unwrap();
    let stranger = Store::open(stranger_dir.path()).unwrap();
    let c = Client::new(&stranger.identity().unwrap(), client.host.clone()).unwrap().with_tcp_only();
    match c.open(&Target::Domain("example.com".into(), 80)).await {
        Err(ClientError::NotPaired) => {}
        other => panic!("expected NotPaired, got {:?}", other.map(|_| ())),
    }
}

#[tokio::test]
async fn tcp_revoke_cuts_live_connection() {
    let env = setup(true).await;
    let client = tcp_client(&env).await;
    let echo = echo_server().await;
    let (mut w, mut r) = client.open(&Target::Addr(echo)).await.unwrap();
    w.write_all(b"hi").await.unwrap();
    w.flush().await.unwrap();
    let mut b = [0u8; 2];
    r.read_exact(&mut b).await.unwrap();
    assert_eq!(env.host.online().len(), 1);

    let id = env.host_store.devices().unwrap()[0].id.clone();
    env.host_store.revoke(&id[..8]).unwrap();
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert!(env.host.online().is_empty());
    let mut rest = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(2), r.read_to_end(&mut rest)).await;
    assert!(matches!(
        client.open(&Target::Addr(echo)).await,
        Err(ClientError::NotPaired)
    ));
}

/// Simulates a network that blocks UDP: the client is pointed at a port
/// where only a TCP relay to the host listens, so QUIC times out.
#[tokio::test]
async fn falls_back_to_tcp_when_udp_is_blocked() {
    let env = setup(true).await;
    let relay = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_port = relay.local_addr().unwrap().port();
    let host_tcp = env.host.local_addr;
    tokio::spawn(async move {
        loop {
            let (mut inbound, _) = relay.accept().await.unwrap();
            tokio::spawn(async move {
                let mut out = TcpStream::connect(host_tcp).await.unwrap();
                let _ = tokio::io::copy_bidirectional(&mut inbound, &mut out).await;
            });
        }
    });

    let identity = env.client_store.identity().unwrap();
    let mut inv = env.invite(600);
    inv.port = relay_port;
    let saved = client::pair(&identity, &inv, "laptop", Some("home")).await.unwrap();
    assert_eq!(env.host_store.devices().unwrap().len(), 1, "paired over TCP");

    let client = Client::new(&identity, saved).unwrap();
    assert_eq!(client.check().await.unwrap(), client::Transport::Tcp);
    let echo = echo_server().await;
    echo_roundtrip(&client, echo, 50_000).await;
}

// ---------------------------------------------------------------------------
// UDP (SOCKS5 UDP ASSOCIATE)
// ---------------------------------------------------------------------------

async fn udp_echo_server() -> SocketAddr {
    let s = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = s.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65_536];
        loop {
            let (n, from) = s.recv_from(&mut buf).await.unwrap();
            let _ = s.send_to(&buf[..n], from).await;
        }
    });
    addr
}

/// Open a SOCKS5 UDP association; returns the control socket (keep it open)
/// and the relay address to send datagrams to.
async fn socks_udp_associate(socks: SocketAddr) -> (TcpStream, SocketAddr) {
    let mut s = TcpStream::connect(socks).await.unwrap();
    s.write_all(&[5, 1, 0]).await.unwrap();
    let mut b2 = [0u8; 2];
    s.read_exact(&mut b2).await.unwrap();
    s.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
    let mut rep = [0u8; 10];
    s.read_exact(&mut rep).await.unwrap();
    assert_eq!(rep[1], 0, "UDP associate accepted");
    let relay = SocketAddr::new(
        std::net::Ipv4Addr::new(rep[4], rep[5], rep[6], rep[7]).into(),
        u16::from_be_bytes([rep[8], rep[9]]),
    );
    (s, relay)
}

fn socks_udp_packet(dest: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut p = vec![0, 0, 0];
    homelink_core::proto::encode_target(&mut p, &Target::Addr(dest));
    p.extend_from_slice(payload);
    p
}

async fn udp_roundtrip(client: Client, allow: bool) {
    let client = Arc::new(client);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socks_addr = listener.local_addr().unwrap();
    tokio::spawn(socks::serve(client, listener));

    let echo = udp_echo_server().await;
    let (_control, relay) = socks_udp_associate(socks_addr).await;
    let app = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    app.send_to(&socks_udp_packet(echo, b"ping over udp"), relay).await.unwrap();
    let mut buf = [0u8; 2048];
    let got = tokio::time::timeout(Duration::from_secs(3), app.recv_from(&mut buf)).await;
    if allow {
        let (n, _) = got.expect("echo reply").unwrap();
        let expected = socks_udp_packet(echo, b"ping over udp");
        assert_eq!(&buf[..n], &expected[..], "reply carries the source address");
    } else {
        assert!(got.is_err(), "local-network UDP must be dropped");
    }
}

#[tokio::test]
async fn udp_through_quic() {
    let env = setup(true).await;
    udp_roundtrip(env.paired_client().await, true).await;
}

#[tokio::test]
async fn udp_through_tcp_fallback() {
    let env = setup(true).await;
    udp_roundtrip(tcp_client(&env).await, true).await;
}

#[tokio::test]
async fn udp_to_local_network_is_dropped() {
    let env = setup(false).await;
    udp_roundtrip(env.paired_client().await, false).await;
}

#[tokio::test]
async fn udp_uses_quic_datagrams_when_they_fit() {
    use homelink_core::proto::{encode_udp_frame, read_udp_frame};
    let env = setup(true).await;
    let client = env.paired_client().await;
    let echo = udp_echo_server().await;
    let mut t = client.open_udp().await.unwrap();
    let d = t.datagrams.as_mut().expect("QUIC gives a datagram path");

    assert!(d.send(&Target::Addr(echo), b"small"), "small packet fits a datagram");
    let (src, payload) = tokio::time::timeout(Duration::from_secs(3), d.recv()).await.unwrap().unwrap();
    assert_eq!((src, payload), (Target::Addr(echo), b"small".to_vec()));

    // Too big for one QUIC datagram: goes as a stream frame both ways.
    let big = vec![7u8; 3000];
    assert!(!d.send(&Target::Addr(echo), &big));
    t.w.write_all(&encode_udp_frame(&Target::Addr(echo), &big).unwrap()).await.unwrap();
    t.w.flush().await.unwrap();
    let (src, payload) = tokio::time::timeout(Duration::from_secs(3), read_udp_frame(&mut t.r))
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(src, Target::Addr(echo));
    assert_eq!(payload.len(), 3000);
}

#[tokio::test]
async fn udp_over_tcp_has_no_datagram_path() {
    let env = setup(true).await;
    let client = tcp_client(&env).await;
    assert!(client.open_udp().await.unwrap().datagrams.is_none());
}
