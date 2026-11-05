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
