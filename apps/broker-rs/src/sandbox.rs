use crate::{env, flag_value, msg, Result};
use std::path::PathBuf;
use tokio::process::Command;

pub async fn run(args: &[String]) -> Result<()> {
    let index = args
        .iter()
        .position(|arg| arg == "--")
        .ok_or_else(|| msg("Put the agent command after --"))?;
    if index + 1 >= args.len() {
        return Err(msg("Missing agent command"));
    }
    let workspace = std::fs::canonicalize(
        flag_value(&args[..index], "--workspace").ok_or_else(|| msg("Missing --workspace"))?,
    )?;
    let user_dir = PathBuf::from(env::var("HOME").map_err(|_| msg("Missing home directory"))?);
    let client = std::fs::canonicalize(env::current_exe()?)?;
    for executable in [
        PathBuf::from(resolve("/opt/homebrew/bin/opgate")),
        PathBuf::from(resolve("/opt/homebrew/bin/op")),
        client.clone(),
    ] {
        if executable.starts_with(&workspace) {
            return Err(msg("Workspace contains a trusted broker executable"));
        }
    }
    for protected in [
        user_dir.join("Library"),
        user_dir.join(".config"),
        user_dir.join(".local"),
        user_dir.join(".ssh"),
        user_dir.join(".codex"),
        user_dir.join(".claude"),
    ] {
        if workspace.starts_with(&protected) || protected.starts_with(&workspace) {
            return Err(msg("Workspace overlaps protected user data"));
        }
    }
    if client.starts_with(&workspace) {
        return Err(msg(
            "Install Keywarden outside the writable workspace before launching an agent",
        ));
    }
    let runtime = std::env::temp_dir().join(format!("keywarden-agent-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&runtime)?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700))?;
    let runtime = std::fs::canonicalize(runtime)?;
    let socket = env::var("KEYWARDEN_SOCKET")
        .unwrap_or_else(|_| "/Users/Shared/Keywarden/broker.sock".into());
    let mut command = Command::new("/usr/bin/sandbox-exec");
    for (key, value) in [
        ("WORKSPACE", workspace.to_string_lossy().into_owned()),
        ("RUNTIME", runtime.to_string_lossy().into_owned()),
        ("CLIENT", client.to_string_lossy().into_owned()),
        ("SOCKET", socket.clone()),
        (
            "TOOLS",
            user_dir
                .join(".local/share/mise/installs")
                .to_string_lossy()
                .into_owned(),
        ),
        ("OPGATE", resolve("/opt/homebrew/bin/opgate")),
        ("OP", resolve("/opt/homebrew/bin/op")),
    ] {
        command.args(["-D", &format!("{key}={value}")]);
    }
    command
        .args(["-p", include_str!("agent.sb")])
        .args(&args[index + 1..]);
    let path = format!(
        "{}:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin",
        client
            .parent()
            .ok_or_else(|| msg("Invalid client path"))?
            .display()
    );
    command
        .env_clear()
        .env("PATH", path)
        .env("HOME", &user_dir)
        .env("TMPDIR", &runtime)
        .env("KEYWARDEN_SOCKET", socket)
        .env("KEYWARDEN_CLIENT", client)
        .current_dir(workspace);
    for key in [
        "TERM",
        "LANG",
        "LC_ALL",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
    ] {
        if let Ok(value) = env::var(key) {
            command.env(key, value);
        }
    }
    let result = command.status().await;
    // Only this invocation owns the runtime directory.
    let _ = std::fs::remove_dir_all(&runtime);
    let code = result?.code().unwrap_or(1);
    if code != 0 {
        std::process::exit(code);
    }
    Ok(())
}

fn resolve(path: &str) -> String {
    std::fs::canonicalize(path)
        .unwrap_or_else(|_| PathBuf::from(path))
        .to_string_lossy()
        .into_owned()
}
