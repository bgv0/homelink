// No console window on Windows release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use homelink_core::client::{self, Client};
use homelink_core::host::{self, Approver, HostHandle, HostOptions, PairRequest};
use homelink_core::portmap::{MapState, PortMapper};
use homelink_core::proto::{self, short_id, Invite};
use homelink_core::store::{HostSettings, SavedHost, Store};
use homelink_core::{reach, socks, stun, sysproxy};
use serde::Serialize;
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager, RunEvent, State, WindowEvent};
use tauri_plugin_autostart::{MacosLauncher, ManagerExt};
use tokio::sync::{oneshot, Mutex};
use tokio::task::JoinHandle;

const PREFERRED_SOCKS: &str = "127.0.0.1:1080";

struct RunningHost {
    handle: HostHandle,
    mapper: Option<PortMapper>,
    public_ip: Option<IpAddr>,
    port: u16,
}

struct RunningClient {
    client: Arc<Client>,
    task: JoinHandle<()>,
    socks: SocketAddr,
    system_proxy: bool,
}

struct AppState {
    store: Store,
    host: Mutex<Option<RunningHost>>,
    client: Mutex<Option<RunningClient>>,
    pending: std::sync::Mutex<HashMap<u64, oneshot::Sender<bool>>>,
    next_request: AtomicU64,
}

type Shared<'a> = State<'a, Arc<AppState>>;
type Res<T> = Result<T, String>;

fn err(e: impl std::fmt::Display) -> String {
    format!("{e:#}")
}

#[derive(Serialize)]
struct DeviceView {
    id: String,
    short: String,
    name: String,
    online: bool,
}

#[derive(Serialize)]
struct SharingView {
    port: u16,
    address: Option<String>,
    router: String,
    router_ok: Option<bool>,
    up: u64,
    down: u64,
}

#[derive(Serialize)]
struct ConnectionView {
    host: String,
    socks: String,
    system_proxy: bool,
    connected: bool,
    rtt_ms: Option<u64>,
    up: u64,
    down: u64,
}

#[derive(Serialize)]
struct Overview {
    device: String,
    settings: HostSettings,
    devices: Vec<DeviceView>,
    hosts: Vec<SavedHost>,
    sharing: Option<SharingView>,
    connection: Option<ConnectionView>,
    autostart: bool,
}

#[tauri::command]
async fn overview(app: AppHandle, state: Shared<'_>) -> Res<Overview> {
    let store = &state.store;
    let host = state.host.lock().await;
    let online: Vec<_> = host.as_ref().map(|h| h.handle.online()).unwrap_or_default();
    let settings = store.settings().map_err(err)?;
    let devices = store
        .devices()
        .map_err(err)?
        .into_iter()
        .map(|d| {
            let id = d.device_id();
            DeviceView {
                short: id.map(|i| short_id(&i)).unwrap_or_default(),
                online: id.is_some_and(|i| online.iter().any(|(o, _)| *o == i)),
                id: d.id,
                name: d.name,
            }
        })
        .collect();
    let sharing = host.as_ref().map(|h| {
        let (router, router_ok) = match &h.mapper {
            None => ("Automatic forwarding is off: forward the port on your router.".to_string(), None),
            Some(m) => match &*m.state.borrow() {
                MapState::Trying => ("Asking your router to forward the port...".to_string(), None),
                MapState::Mapped { .. } => ("Port forwarded automatically by your router.".to_string(), Some(true)),
                MapState::Unavailable(e) => (format!("{e}. Forward the port on your router by hand."), Some(false)),
            },
        };
        SharingView {
            port: h.port,
            address: settings.public_addr.clone().or(h.public_ip.map(|i| i.to_string())),
            router,
            router_ok,
            up: h.handle.traffic.up.load(Ordering::Relaxed),
            down: h.handle.traffic.down.load(Ordering::Relaxed),
        }
    });
    drop(host);
    let connection = match state.client.lock().await.as_ref() {
        Some(c) => {
            let rtt = c.client.rtt().await;
            Some(ConnectionView {
                host: c.client.host.name.clone(),
                socks: c.socks.to_string(),
                system_proxy: c.system_proxy,
                connected: rtt.is_some(),
                rtt_ms: rtt.map(|d| d.as_millis() as u64),
                up: c.client.traffic.up.load(Ordering::Relaxed),
                down: c.client.traffic.down.load(Ordering::Relaxed),
            })
        }
        None => None,
    };
    Ok(Overview {
        device: store.identity().map(|i| short_id(&i.id)).map_err(err)?,
        settings,
        devices,
        hosts: store.hosts().map_err(err)?,
        sharing,
        connection,
        autostart: app.autolaunch().is_enabled().unwrap_or(false),
    })
}

fn approver(app: AppHandle, state: Arc<AppState>) -> Approver {
    Arc::new(move |req: PairRequest| {
        let app = app.clone();
        let state = state.clone();
        Box::pin(async move {
            let id = state.next_request.fetch_add(1, Ordering::Relaxed);
            let (tx, rx) = oneshot::channel();
            state.pending.lock().unwrap().insert(id, tx);
            show_window(&app);
            let _ = app.emit(
                "pair-request",
                serde_json::json!({ "request": id, "name": req.name, "device": short_id(&req.id) }),
            );
            let allowed = tokio::time::timeout(Duration::from_secs(110), rx)
                .await
                .ok()
                .and_then(|r| r.ok())
                .unwrap_or(false);
            state.pending.lock().unwrap().remove(&id);
            let _ = app.emit("pair-request-done", id);
            allowed
        })
    })
}

#[tauri::command]
fn answer_pair(state: Shared<'_>, request: u64, allow: bool) {
    if let Some(tx) = state.pending.lock().unwrap().remove(&request) {
        let _ = tx.send(allow);
    }
}

async fn start_host(app: &AppHandle, state: &Arc<AppState>) -> Res<()> {
    let mut slot = state.host.lock().await;
    if slot.is_some() {
        return Ok(());
    }
    let s = state.store.settings().map_err(err)?;
    let mut opts = HostOptions::from_settings(&s);
    let public_ip = stun::public_ip().await;
    if let Some(ip) = public_ip {
        opts.blocked.push(ip);
    }
    let handle = host::start(state.store.clone(), opts, approver(app.clone(), state.clone()))
        .await
        .map_err(err)?;
    let mapper = s.upnp.then(|| PortMapper::start(s.port));
    *slot = Some(RunningHost { handle, mapper, public_ip, port: s.port });
    Ok(())
}

#[tauri::command]
async fn start_sharing(app: AppHandle, state: Shared<'_>) -> Res<()> {
    start_host(&app, state.inner()).await
}

async fn stop_host(state: &AppState) {
    if let Some(h) = state.host.lock().await.take() {
        h.handle.shutdown().await;
        if let Some(m) = h.mapper {
            m.stop().await;
        }
    }
}

#[tauri::command]
async fn stop_sharing(state: Shared<'_>) -> Res<()> {
    stop_host(state.inner()).await;
    Ok(())
}

#[tauri::command]
async fn save_settings(state: Shared<'_>, settings: HostSettings) -> Res<()> {
    if settings.port == 0 {
        return Err("Port must be between 1 and 65535.".into());
    }
    let mut s = settings;
    s.public_addr = s.public_addr.map(|a| a.trim().to_string()).filter(|a| !a.is_empty());
    if let Some(a) = &s.public_addr {
        if !proto::valid_host_addr(a) {
            return Err(format!("'{a}' isn't a valid hostname or IP address."));
        }
    }
    state.store.save_settings(&s).map_err(err)
}

#[tauri::command]
fn set_autostart(app: AppHandle, enabled: bool) -> Res<()> {
    let al = app.autolaunch();
    if enabled { al.enable() } else { al.disable() }.map_err(err)
}

#[tauri::command]
async fn create_invite(state: Shared<'_>, minutes: u64) -> Res<String> {
    let s = state.store.settings().map_err(err)?;
    let addr = match s.public_addr {
        Some(a) => a,
        None => stun::public_ip()
            .await
            .ok_or("Couldn't detect your public address. Enter it (or a DDNS name) in settings.")?
            .to_string(),
    };
    let id = state.store.identity().map_err(err)?.id;
    let inv = state
        .store
        .create_invite(id, addr, s.port, minutes.clamp(1, 24 * 60) * 60)
        .map_err(err)?;
    Ok(inv.encode())
}

#[tauri::command]
fn revoke(state: Shared<'_>, id: String) -> Res<()> {
    state.store.revoke(&id).map(|_| ()).map_err(err)
}

#[tauri::command]
async fn check_network() -> Res<reach::Report> {
    Ok(reach::check().await)
}

#[tauri::command]
async fn add_host(state: Shared<'_>, code: String, name: Option<String>) -> Res<SavedHost> {
    let inv = Invite::decode(&code).map_err(err)?;
    let identity = state.store.identity().map_err(err)?;
    let saved = client::pair(&identity, &inv, &computer_name(), name.as_deref())
        .await
        .map_err(err)?;
    state.store.save_host(saved.clone()).map_err(err)?;
    Ok(saved)
}

#[tauri::command]
async fn remove_host(state: Shared<'_>, name: String) -> Res<()> {
    let connected_to = state.client.lock().await.as_ref().map(|c| c.client.host.name.clone());
    if connected_to.as_deref() == Some(name.as_str()) {
        disconnect_client(state.inner()).await;
    }
    state.store.remove_host(&name).map(|_| ()).map_err(err)
}

#[tauri::command]
async fn connect(state: Shared<'_>, name: String, system_proxy: bool) -> Res<()> {
    disconnect_client(state.inner()).await;
    let saved = state.store.find_host(Some(&name)).map_err(err)?;
    let client = Arc::new(Client::new(&state.store.identity().map_err(err)?, saved).map_err(err)?);
    client.connection().await.map_err(err)?;
    let listener = match tokio::net::TcpListener::bind(PREFERRED_SOCKS).await {
        Ok(l) => l,
        Err(_) => tokio::net::TcpListener::bind("127.0.0.1:0").await.map_err(err)?,
    };
    let socks_addr = listener.local_addr().map_err(err)?;
    let task = tokio::spawn({
        let client = client.clone();
        async move {
            let _ = socks::serve(client, listener).await;
        }
    });
    let mut running = RunningClient { client, task, socks: socks_addr, system_proxy: false };
    if system_proxy {
        if let Err(e) = sysproxy::enable(state.store.dir(), socks_addr) {
            running.task.abort();
            running.client.disconnect().await;
            return Err(err(e));
        }
        running.system_proxy = true;
    }
    *state.client.lock().await = Some(running);
    Ok(())
}

async fn disconnect_client(state: &AppState) {
    if let Some(c) = state.client.lock().await.take() {
        if c.system_proxy {
            sysproxy::recover(state.store.dir());
        }
        c.task.abort();
        c.client.disconnect().await;
    }
}

#[tauri::command]
async fn disconnect(state: Shared<'_>) -> Res<()> {
    disconnect_client(state.inner()).await;
    Ok(())
}

fn computer_name() -> String {
    let mut cmd = std::process::Command::new("hostname");
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000);
    }
    cmd.output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| proto::sanitize_name(s.trim().trim_end_matches(".local")))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "device".into())
}

fn show_window(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        let _ = w.unminimize();
        let _ = w.set_focus();
    }
}

async fn cleanup(state: &AppState) {
    disconnect_client(state).await;
    stop_host(state).await;
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("HOMELINK_LOG")
                .unwrap_or_else(|_| "warn".into()),
        )
        .init();

    let store = Store::open_default().expect("couldn't open the homelink data folder");
    // Undo a system proxy change left behind if the app crashed while connected.
    sysproxy::recover(store.dir());
    let state = Arc::new(AppState {
        store,
        host: Mutex::new(None),
        client: Mutex::new(None),
        pending: std::sync::Mutex::new(HashMap::new()),
        next_request: AtomicU64::new(1),
    });

    let app = tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| show_window(app)))
        .plugin(tauri_plugin_autostart::init(MacosLauncher::LaunchAgent, Some(vec!["--background"])))
        .manage(state.clone())
        .invoke_handler(tauri::generate_handler![
            overview,
            answer_pair,
            start_sharing,
            stop_sharing,
            save_settings,
            set_autostart,
            create_invite,
            revoke,
            check_network,
            add_host,
            remove_host,
            connect,
            disconnect,
        ])
        .setup(move |app| {
            let show = MenuItem::with_id(app, "show", "Open homelink", true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show, &quit])?;
            TrayIconBuilder::with_id("tray")
                .icon(app.default_window_icon().cloned().expect("app icon"))
                .tooltip("homelink")
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "show" => show_window(app),
                    "quit" => app.exit(0),
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        show_window(tray.app_handle());
                    }
                })
                .build(app)?;

            // Launched at login: stay in the tray.
            if std::env::args().any(|a| a == "--background") {
                if let Some(w) = app.get_webview_window("main") {
                    let _ = w.hide();
                }
            }

            let st = app.state::<Arc<AppState>>().inner().clone();
            if st.store.settings().map(|s| s.share_on_launch).unwrap_or(false) {
                let handle = app.handle().clone();
                tauri::async_runtime::spawn(async move {
                    if let Err(e) = start_host(&handle, &st).await {
                        tracing::warn!("couldn't start sharing: {e}");
                    }
                });
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            // Closing the window keeps homelink running in the tray.
            if let WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .build(tauri::generate_context!())
        .expect("error while building homelink");

    app.run(move |_app, event| {
        if let RunEvent::Exit = event {
            tauri::async_runtime::block_on(cleanup(&state));
        }
    });
}
