//! Rahyab Android JNI core.
//!
//! Two independent pieces, driven from Kotlin:
//!  1. `startEngine(configJson)` → binds 127.0.0.1:<random> (the local SOCKS hub),
//!     spawns the Khorshid supervisor (probe/plan/race/watch). Returns the hub port.
//!  2. `startTunnel(fd, mtu, hubPort)` → hands the VpnService tun file descriptor to
//!     tun2proxy, pointed at the hub. Runs until `stopTunnel()`.
//!
//! Because failover happens INSIDE the hub (hot upstream swap), the VPN interface does
//! not need to be rebuilt when the underlying tunnel changes.

use jni::objects::{JClass, JString};
use jni::sys::{jint, jstring};
use jni::JNIEnv;
use std::sync::{Arc, Mutex, OnceLock};

struct Handles {
    engine_stop: tokio::sync::watch::Sender<bool>,
    tun_cancel: tun2proxy::CancellationToken,
    status: Arc<rahyab_core::algo::EngineShared>,
}

static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
static HANDLES: Mutex<Option<Handles>> = Mutex::new(None);

fn rt() -> &'static tokio::runtime::Runtime {
    RT.get_or_init(|| {
        #[cfg(target_os = "android")]
        {
            android_logger::init_once(
                android_logger::Config::default()
                    .with_tag("rahyab")
                    .with_max_level(log::LevelFilter::Info),
            );
        }
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("tokio runtime")
    })
}

fn jstr(env: &mut JNIEnv, s: &str) -> jstring {
    env.new_string(s)
        .map(|j| j.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

#[no_mangle]
pub extern "system" fn Java_app_rahyab_vpn_RustCore_startEngine(
    mut env: JNIEnv,
    _class: JClass,
    config_json: JString,
) -> jint {
    let cfg_s: String = match env.get_string(&config_json) {
        Ok(s) => s.into(),
        Err(_) => return -1,
    };
    let cfg = match rahyab_core::config::AppConfig::from_json(&cfg_s) {
        Ok(c) => c,
        Err(e) => {
            log::error!("bad config: {e}");
            return -2;
        }
    };

    let runtime = rt();
    let listener = match runtime
        .block_on(async { tokio::net::TcpListener::bind("127.0.0.1:0").await })
    {
        Ok(l) => l,
        Err(e) => {
            log::error!("hub bind: {e}");
            return -3;
        }
    };
    let port = listener.local_addr().map(|a| a.port()).unwrap_or(0);

    let shared = Arc::new(rahyab_core::algo::EngineShared::new());
    shared.update(|s| s.hub_addr = listener.local_addr().ok());
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let shared2_status = shared.clone();

    // Optional local hop (e.g. embedded Psiphon library's local SOCKS5).
    let hop: Option<rahyab_core::transport::SharedConnector> = cfg.local_hops.first().map(|h| {
        use rahyab_core::transport::socks5::Socks5Connector;
        use rahyab_core::transport::TargetAddr;
        let (h2, p2) = h.socks.rsplit_once(':').expect("hop socks host:port");
        Arc::new(Socks5Connector::new(TargetAddr::Domain(
            h2.to_string(),
            p2.parse().expect("hop port"),
        ))) as rahyab_core::transport::SharedConnector
    });

    let mem_path = cfg
        .memory_path
        .clone()
        .unwrap_or_else(|| "rahyab_memory.json".to_string());

    {
        let shared2 = shared.clone();
        runtime.spawn(rahyab_core::hub::serve_hub(
            listener,
            shared2.hub_current.clone(),
            stop_rx.clone(),
        ));
    }
    runtime.spawn(rahyab_core::algo::supervise(
        cfg,
        mem_path.into(),
        shared,
        stop_rx,
        hop,
    ));

    if HANDLES
        .lock()
        .unwrap()
        .replace(Handles {
            engine_stop: stop_tx,
            tun_cancel: tun2proxy::CancellationToken::new(),
            status: shared2_status,
        })
        .is_some()
    {
        log::warn!("startEngine called while an engine was already running");
    }
    port as jint
}

#[no_mangle]
pub extern "system" fn Java_app_rahyab_vpn_RustCore_stopEngine(_env: JNIEnv, _class: JClass) {
    if let Ok(mut h) = HANDLES.lock() {
        if let Some(h) = h.take() {
            let _ = h.engine_stop.send(true);
            h.tun_cancel.cancel();
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_app_rahyab_vpn_RustCore_statusJson(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    let json = HANDLES
        .lock()
        .ok()
        .and_then(|h| h.as_ref().map(|h| h.status.status_json()))
        .unwrap_or_else(|| "{}".to_string());
    jstr(&mut env, &json)
}

#[no_mangle]
pub extern "system" fn Java_app_rahyab_vpn_RustCore_startTunnel(
    _env: JNIEnv,
    _class: JClass,
    fd: jint,
    mtu: jint,
    hub_port: jint,
) -> jint {
    start_tunnel_impl(fd, mtu, hub_port)
}

#[cfg(unix)]
fn start_tunnel_impl(fd: jint, mtu: jint, hub_port: jint) -> jint {
    let Some(cancel) = HANDLES.lock().ok().and_then(|h| h.as_ref().map(|h| h.tun_cancel.clone()))
    else {
        log::error!("startTunnel before startEngine");
        return -1;
    };

    let mut args = tun2proxy::Args::default();
    args.tun_fd = Some(fd);
    args.close_fd_on_drop = Some(false);
    let mtu_u16: u16 = mtu.max(576).min(1600) as u16;
    args.verbosity = tun2proxy::LevelFilter::Info;
    args.dns(tun2proxy::ArgDns::Virtual);
    // Upstream = our local hub; the Khorshid supervisor decides what's behind it.
    let proxy_url = format!("socks5://127.0.0.1:{hub_port}");
    args.proxy = match tun2proxy::ProxyParameters::try_from(proxy_url.as_str()) {
        Ok(p) => p,
        Err(e) => {
            log::error!("proxy params: {e}");
            return -2;
        }
    };

    let cancel2 = cancel.clone();
    rt().spawn(async move {
        let _ = tun2proxy::general_run_async(args, mtu_u16, false, cancel2).await;
    });
    0
}

/// Host builds (Windows) have no tun fd path — keeps `cargo check --workspace` green.
#[cfg(not(unix))]
fn start_tunnel_impl(_fd: jint, _mtu: jint, _hub_port: jint) -> jint {
    log::warn!("startTunnel is only available on unix/android targets");
    -100
}

#[no_mangle]
pub extern "system" fn Java_app_rahyab_vpn_RustCore_stopTunnel(_env: JNIEnv, _class: JClass) {
    if let Ok(h) = HANDLES.lock() {
        if let Some(h) = h.as_ref() {
            h.tun_cancel.cancel();
        }
    }
}
