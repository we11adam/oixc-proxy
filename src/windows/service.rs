//! Native SCM service lifecycle. Stop/shutdown share the CLI's final traffic flush.
use std::ffi::OsString;
use std::io::{Seek, SeekFrom};
use std::os::windows::io::AsRawHandle;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use tokio::sync::Notify;
use windows_service::service::*;
use windows_service::service_control_handler::{
    self, ServiceControlHandlerResult, ServiceStatusHandle,
};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

pub const NAME: &str = "oixc-proxy";
static STATE: OnceLock<State> = OnceLock::new();

#[derive(Default)]
struct State {
    stop: Notify,
    stopping: AtomicBool,
    handle: Mutex<Option<ServiceStatusHandle>>,
}
fn state() -> &'static State {
    STATE.get_or_init(State::default)
}

fn status(current_state: ServiceState, exit: u32) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state,
        controls_accepted: if current_state == ServiceState::Running {
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
        } else {
            ServiceControlAccept::empty()
        },
        exit_code: ServiceExitCode::Win32(exit),
        checkpoint: u32::from(matches!(
            current_state,
            ServiceState::StartPending | ServiceState::StopPending
        )),
        wait_hint: if matches!(
            current_state,
            ServiceState::StartPending | ServiceState::StopPending
        ) {
            Duration::from_secs(60)
        } else {
            Duration::ZERO
        },
        process_id: None,
    }
}

pub async fn stopping() {
    state().stop.notified().await;
}

pub fn is_service() -> bool {
    state().handle.lock().unwrap().is_some()
}

/// Called only after listeners and the private control endpoint are bound.
pub fn ready() -> Result<()> {
    let handle = state().handle.lock().unwrap();
    if let Some(handle) = *handle {
        if !state().stopping.load(Ordering::Acquire) {
            handle.set_service_status(status(ServiceState::Running, 0))?;
        }
    }
    Ok(())
}

windows_service::define_windows_service!(ffi_main, service_main);

pub fn dispatch() -> Result<()> {
    windows_service::service_dispatcher::start(NAME, ffi_main)
        .context("connect Windows service dispatcher (run this command through SCM)")
}

fn service_main(_arguments: Vec<OsString>) {
    let handler = |control| match control {
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        ServiceControl::Stop | ServiceControl::Shutdown => {
            state().stopping.store(true, Ordering::Release);
            if let Some(handle) = *state().handle.lock().unwrap() {
                let _ = handle.set_service_status(status(ServiceState::StopPending, 0));
            }
            state().stop.notify_one();
            ServiceControlHandlerResult::NoError
        }
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let Ok(handle) = service_control_handler::register(NAME, handler) else {
        return;
    };
    *state().handle.lock().unwrap() = Some(handle);
    let _ = handle.set_service_status(status(ServiceState::StartPending, 0));
    let result = run_worker();
    if let Err(error) = &result {
        eprintln!("Windows service failed: {error:#}");
    }
    // Cleanup and traffic flush have completed before reporting Stopped.
    *state().handle.lock().unwrap() = None;
    let _ = handle.set_service_status(status(
        ServiceState::Stopped,
        if result.is_ok() { 0 } else { 1 },
    ));
}

fn run_worker() -> Result<()> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    if arguments.len() != 3 || arguments[0] != "windows-service" || arguments[1] != "--config" {
        bail!("windows-service requires --config PATH");
    }
    let config = Path::new(&arguments[2]);
    let working = config
        .parent()
        .context("configuration has no parent directory")?;
    std::env::set_current_dir(working).context("set service working directory")?;
    let mut log = super::files::open_private(&working.join("oixc-proxy.log"), true, false)?;
    log.seek(SeekFrom::End(0))?;
    // Rust's stdout/stderr use the process standard handles, including in a
    // noninteractive service. Keep this File alive until the worker exits.
    use windows_sys::Win32::System::Console::{STD_ERROR_HANDLE, STD_OUTPUT_HANDLE, SetStdHandle};
    if unsafe { SetStdHandle(STD_OUTPUT_HANDLE, log.as_raw_handle()) } == 0
        || unsafe { SetStdHandle(STD_ERROR_HANDLE, log.as_raw_handle()) } == 0
    {
        return Err(std::io::Error::last_os_error()).context("redirect service logs");
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let exit = runtime.block_on(crate::cli::run(vec![
        "serve".into(),
        "--config".into(),
        arguments[2].clone(),
    ]));
    // Drop all remaining connection tasks before closing the log/reporting Stopped.
    runtime.shutdown_timeout(Duration::from_secs(5));
    log.sync_all()?;
    if exit != 0 {
        bail!("service worker exited with code {exit}; see oixc-proxy.log");
    }
    Ok(())
}

pub fn install(config: &Path) -> Result<()> {
    let config = config
        .canonicalize()
        .context("locate service configuration")?;
    crate::config::load_proxy_config(&config)?;
    let executable = std::env::current_exe()?.canonicalize()?;
    // A SYSTEM service must never execute from Downloads, a temp directory or
    // a user-writable checkout. install.ps1 prepares this protected location.
    let program_files = std::env::var_os("ProgramFiles").context("locate ProgramFiles")?;
    let program_files = Path::new(&program_files).canonicalize()?;
    if !executable.starts_with(&program_files) {
        bail!("install the executable under ProgramFiles first (use install.ps1)");
    }
    super::files::validate_private(&std::fs::File::open(&executable)?)?;
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .context("open service manager; run PowerShell as Administrator")?;
    let info = ServiceInfo {
        name: NAME.into(),
        display_name: "oixc-proxy".into(),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: executable,
        launch_arguments: vec![
            "windows-service".into(),
            "--config".into(),
            config.into_os_string(),
        ],
        dependencies: vec![],
        account_name: None,
        account_password: None,
    };
    // CreateService refuses an existing registration; never overwrite it.
    let service = manager
        .create_service(
            &info,
            ServiceAccess::CHANGE_CONFIG | ServiceAccess::START | ServiceAccess::QUERY_STATUS,
        )
        .context("create oixc-proxy service (existing services are not overwritten)")?;
    service.set_description("oixCloud local HTTP/SOCKS5 proxy")?;
    service.set_delayed_auto_start(true)?;
    service.update_failure_actions(ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(86400)),
        reboot_msg: None,
        command: None,
        actions: Some(vec![ServiceAction {
            action_type: ServiceActionType::Restart,
            delay: Duration::from_secs(5),
        }]),
    })?;
    service.set_failure_actions_on_non_crash_failures(true)?;
    service.start::<&str>(&[])?;
    wait(&service, ServiceState::Running)?;
    println!(
        "Installed and started Windows service {NAME} (LocalSystem, delayed automatic start)."
    );
    Ok(())
}

fn wait(service: &Service, wanted: ServiceState) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let status = service.query_status()?;
        if status.current_state == wanted {
            return Ok(());
        }
        if wanted == ServiceState::Running && status.current_state == ServiceState::Stopped {
            bail!(
                "Windows service failed to start; inspect oixc-proxy.log and the System event log"
            );
        }
        if Instant::now() >= deadline {
            bail!(
                "timed out waiting for Windows service {wanted:?}; registration and files retained"
            );
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

pub fn uninstall() -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(
        NAME,
        ServiceAccess::STOP | ServiceAccess::QUERY_STATUS | ServiceAccess::DELETE,
    )?;
    match service.query_status()?.current_state {
        ServiceState::Stopped => {}
        ServiceState::StopPending => wait(&service, ServiceState::Stopped)?,
        _ => {
            service.stop()?;
            wait(&service, ServiceState::Stopped)?;
        }
    }
    service.delete()?;
    println!(
        "Removed Windows service {NAME}; executable, config, logs and traffic history retained."
    );
    Ok(())
}
