//! Running the daemon: directories, sockets, the lifecycle file, and the
//! shutdown on a signal.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, anyhow};
use mirror_client::{Lifecycle, MirrorDirs};
use tokio::net::UnixListener;
use tokio_util::sync::CancellationToken;

use crate::git::Repos;
use crate::origin::Origins;
use crate::server::{Mirror, Role, serve};
use crate::state::{AliveLock, write};
use crate::store::Store;

fn bind(path: &Path) -> anyhow::Result<UnixListener> {
    if path.exists() {
        fs::remove_file(path).with_context(|| format!("removing a stale {}", path.display()))?;
    }
    let listener =
        UnixListener::bind(path).with_context(|| format!("binding {}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("restricting {}", path.display()))?;
    Ok(listener)
}

/// Runs the daemon in the foreground until a termination signal.
pub async fn run(dirs: MirrorDirs) -> anyhow::Result<()> {
    fs::create_dir_all(&dirs.state)
        .with_context(|| format!("creating {}", dirs.state.display()))?;
    fs::set_permissions(&dirs.state, fs::Permissions::from_mode(0o700))?;
    let lock = match AliveLock::try_acquire(&dirs.alive_lock())? {
        Some(lock) => lock,
        None => {
            // Another daemon holds the lock: a starter that raced us. Wait
            // for its socket so our starter sees a running mirror (MIR-070).
            let deadline = Instant::now() + mirror_client::START_TIMEOUT;
            while Instant::now() < deadline {
                if mirror_client::running(&dirs).is_some() {
                    tracing::info!("another mirror daemon is running; leaving it to serve");
                    return Ok(());
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            return Err(anyhow!(
                "another mirror daemon holds the lock but answers on no socket"
            ));
        }
    };
    let store = Store::new(dirs.store.clone());
    store
        .init()
        .with_context(|| format!("preparing the store at {}", dirs.store.display()))?;
    write(&dirs, Lifecycle::Starting)?;

    let host = bind(&dirs.host_socket())?;
    let door = bind(&dirs.door_socket())?;
    let mirror = Arc::new(Mirror {
        origins: Origins::new(store.clone()),
        repos: Repos::new(store.clone()),
        store,
        dirs: dirs.clone(),
    });
    write(&dirs, Lifecycle::Running)?;
    tracing::info!(
        host = %dirs.host_socket().display(),
        door = %dirs.door_socket().display(),
        store = %dirs.store.display(),
        "mirror running"
    );

    let shutdown = CancellationToken::new();
    let host_task = tokio::spawn(serve(mirror.clone(), host, Role::Host, shutdown.clone()));
    let door_task = tokio::spawn(serve(mirror.clone(), door, Role::Door, shutdown.clone()));

    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut int = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    tokio::select! {
        _ = term.recv() => tracing::info!("stopping on SIGTERM"),
        _ = int.recv() => tracing::info!("stopping on SIGINT"),
    }
    write(&dirs, Lifecycle::Stopping)?;
    shutdown.cancel();
    let _ = host_task.await;
    let _ = door_task.await;
    let _ = fs::remove_file(dirs.host_socket());
    let _ = fs::remove_file(dirs.door_socket());
    write(&dirs, Lifecycle::Stopped)?;
    drop(lock);
    Ok(())
}
