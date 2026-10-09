use crate::{msg, Result};
use std::{
    path::{Path, PathBuf},
    process::{Output, Stdio},
    time::Duration,
};
use tokio::process::Command;
use uuid::Uuid;

struct Daemon {
    child: tokio::process::Child,
    pid: Option<u32>,
    socket: PathBuf,
}

impl Daemon {
    async fn start() -> Result<Self> {
        let binary = std::env::var("KEYWARDEN_OP_CLI").unwrap_or_else(|_| "op".into());
        Self::start_command(Command::new(binary)).await
    }

    async fn start_command(mut command: Command) -> Result<Self> {
        let socket = PathBuf::from(format!("/tmp/keywarden-op-{}.sock", Uuid::new_v4()));
        command
            .args(["daemon", "--timeout", "60s"])
            .env("OP_LOAD_DESKTOP_APP_SETTINGS", "false")
            .env("OP_BIOMETRIC_UNLOCK_ENABLED", "false")
            .env("OP_CACHE", "false")
            .env("OP_SOCK", &socket)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0)
            .kill_on_drop(true);
        let mut child = command.spawn().map_err(|error| {
            msg(format!(
                "Could not start the isolated 1Password daemon: {error}"
            ))
        })?;
        let pid = child
            .id()
            .ok_or_else(|| msg("Isolated 1Password daemon did not start"))?;
        let ready = async {
            loop {
                if socket.exists() {
                    return Ok(Some(pid));
                }
                if let Some(status) = child.try_wait()? {
                    // Some op versions make `daemon` a successful no-op. The
                    // uncached service-account command can run without it.
                    if status.success() {
                        return Ok(None);
                    }
                    return Err(msg(format!(
                        "1Password daemon startup failed before opening its private socket ({status})"
                    )));
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        };
        let pid = match tokio::time::timeout(Duration::from_secs(2), ready).await {
            Ok(Ok(pid)) => pid,
            Ok(Err(error)) => {
                stop_process_group(pid).await;
                return Err(error);
            }
            Err(_) => {
                stop_process_group(pid).await;
                return Err(msg("Isolated 1Password daemon did not open its socket"));
            }
        };
        Ok(Self { child, pid, socket })
    }

    async fn stop(mut self) {
        if let Some(pid) = self.pid {
            stop_process_group(pid).await;
        }
        let _ = self.child.wait().await;
        let _ = std::fs::remove_file(self.socket);
    }
}

async fn stop_process_group(pid: u32) {
    let _ = Command::new("/bin/kill")
        .args(["-KILL", "--", &format!("-{pid}")])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await;
}

fn needs_daemon(command: &Command) -> bool {
    Path::new(command.as_std().get_program())
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == "op" || name == "opgate")
}

// Service accounts use opgate credentials, not the desktop application's data.
// Keep these settings local to the child; native Apple setup still uses approval.
pub async fn output(mut command: Command, timeout: Duration) -> Result<Output> {
    let mut daemon = if needs_daemon(&command) {
        Some(Daemon::start().await?)
    } else {
        None
    };
    command
        .env("OP_LOAD_DESKTOP_APP_SETTINGS", "false")
        .env("OP_BIOMETRIC_UNLOCK_ENABLED", "false")
        .env("OP_CACHE", "false")
        .process_group(0)
        .kill_on_drop(true);
    if let Some(value) = daemon.as_ref() {
        command.env("OP_SOCK", &value.socket);
    }
    let child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            if let Some(daemon) = daemon.take() {
                daemon.stop().await;
            }
            return Err(error.into());
        }
    };
    let pid = match child.id() {
        Some(pid) => pid,
        None => {
            if let Some(daemon) = daemon.take() {
                daemon.stop().await;
            }
            return Err(msg("Provider process did not start"));
        }
    };
    let output = match tokio::time::timeout(timeout, child.wait_with_output()).await {
        Ok(result) => result.map_err(Into::into),
        Err(_) => {
            // opgate starts shell and op children. Killing only its parent leaves
            // those children running, including blocked macOS permission prompts.
            stop_process_group(pid).await;
            if let Some(daemon) = daemon.take() {
                daemon.stop().await;
            }
            Err(msg(
                "1Password command timed out; its process group was stopped",
            ))
        }
    };
    if let Some(daemon) = daemon {
        daemon.stop().await;
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn service_account_child_does_not_load_desktop_settings() {
        let mut command = Command::new("/bin/sh");
        command.env("OP_LOAD_DESKTOP_APP_SETTINGS", "true")
            .env("OP_BIOMETRIC_UNLOCK_ENABLED", "true")
            .env("OP_CACHE", "true")
            .args(["-c", "test \"$OP_LOAD_DESKTOP_APP_SETTINGS\" = false && test \"$OP_BIOMETRIC_UNLOCK_ENABLED\" = false && test \"$OP_CACHE\" = false"]);
        assert!(output(command, Duration::from_secs(5))
            .await
            .unwrap()
            .status
            .success());
    }

    #[tokio::test]
    async fn timeout_stops_descendants() {
        let directory =
            std::env::temp_dir().join(format!("keywarden-provider-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        let marker = directory.join("child-survived");
        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", "(sleep 1; touch \"$1\") & wait", "provider-test"])
            .arg(&marker)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let error = output(command, Duration::from_millis(200))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("process group was stopped"));
        tokio::time::sleep(Duration::from_millis(1200)).await;
        assert!(!marker.exists(), "provider child survived the timeout");
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn only_1password_commands_get_an_owned_daemon() {
        assert!(needs_daemon(&Command::new("op")));
        assert!(needs_daemon(&Command::new("opgate")));
        assert!(!needs_daemon(&Command::new("/bin/sh")));
    }

    #[tokio::test]
    async fn owned_daemon_stops_without_leaking_a_process() {
        let available = std::process::Command::new("op")
            .arg("--version")
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false);
        if !available {
            return;
        }
        let daemon = Daemon::start().await.unwrap();
        let pid = daemon.pid;
        let socket = daemon.socket.clone();
        if pid.is_some() {
            assert!(socket.exists());
        }
        daemon.stop().await;
        assert!(!socket.exists());
        if let Some(pid) = pid {
            assert!(!std::process::Command::new("/bin/kill")
                .args(["-0", &pid.to_string()])
                .stderr(Stdio::null())
                .status()
                .unwrap()
                .success());
        }
    }

    #[tokio::test]
    async fn successful_noop_daemon_allows_uncached_provider_commands() {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "exit 0"]);
        let daemon = Daemon::start_command(command).await.unwrap();
        assert!(daemon.pid.is_none());
        assert!(!daemon.socket.exists());
        daemon.stop().await;
    }

    #[tokio::test]
    async fn unsuccessful_daemon_still_fails_closed() {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "exit 7"]);
        let result = Daemon::start_command(command).await;
        let error = result.err().expect("nonzero daemon exit must fail");
        assert!(error.to_string().contains("startup failed"));
        assert!(error.to_string().contains('7'));
    }
}
