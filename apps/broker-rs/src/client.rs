use crate::{msg, ClientMetadata, Result, Value};
use std::{env, path::Path, process};

pub(crate) fn cli_metadata(
    agent: Option<&str>,
    host: Option<&str>,
    session_name: Option<&str>,
) -> Result<ClientMetadata> {
    let ancestors = ancestor_names();
    cli_metadata_with(agent, host, session_name, &ancestors, &|key| {
        env::var(key).ok()
    })
}

fn cli_metadata_with(
    agent: Option<&str>,
    host: Option<&str>,
    session_name: Option<&str>,
    ancestors: &[String],
    environment: &impl Fn(&str) -> Option<String>,
) -> Result<ClientMetadata> {
    let detected = detect_cli_product(ancestors, environment);
    let name = agent.unwrap_or(match detected {
        "codex" => "Codex",
        "claude-code" => "Claude Code",
        _ => "Keywarden CLI",
    });
    check_metadata_text(name)?;
    let (known_product, known_display) = normalize_client(name);
    let product = if known_product == "mcp" {
        "cli"
    } else {
        known_product
    };
    let session_name = session_name
        .map(str::to_owned)
        .or_else(|| session_environment_with(product, "NAME", environment));
    let session_id = session_environment_with(product, "ID", environment);
    let host = host
        .map(str::to_owned)
        .or_else(|| environment("HOSTNAME"))
        .unwrap_or_else(|| "Mac".into());
    check_metadata_text(&host)?;
    for value in [&session_name, &session_id].into_iter().flatten() {
        check_metadata_text(value)?;
    }
    Ok(ClientMetadata {
        product: product.into(),
        client_name: name.into(),
        display_name: if known_product == "mcp" {
            name.into()
        } else {
            known_display.into()
        },
        product_version: "unknown".into(),
        protocol_version: "local".into(),
        transport: "cli".into(),
        session_id,
        session_name,
        host,
        project: current_project(),
        pid: Some(process::id()),
        capabilities: vec![],
    })
}

// Inspect executable names only. Process arguments can contain credentials.
fn ancestor_names() -> Vec<String> {
    let mut names = Vec::new();
    let mut pid = process::id();
    for _ in 0..12 {
        let Ok(output) = process::Command::new("/bin/ps")
            .args(["-p", &pid.to_string(), "-o", "ppid=,comm="])
            .output()
        else {
            break;
        };
        if !output.status.success() {
            break;
        }
        let line = String::from_utf8_lossy(&output.stdout);
        let Some((parent, name)) = line.trim().split_once(char::is_whitespace) else {
            break;
        };
        let Ok(parent) = parent.trim().parse::<u32>() else {
            break;
        };
        names.push(name.trim().to_owned());
        if parent <= 1 || parent == pid {
            break;
        }
        pid = parent;
    }
    names
}

fn detect_cli_product(
    ancestors: &[String],
    environment: &impl Fn(&str) -> Option<String>,
) -> &'static str {
    for executable in ancestors {
        let name = Path::new(executable)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        match name.as_str() {
            "codex" | "codex.exe" => return "codex",
            "claude" | "claude-code" | "claude.exe" => return "claude-code",
            _ => (),
        }
    }
    let present = |names: &[&str]| {
        names
            .iter()
            .any(|key| environment(key).is_some_and(|value| !value.trim().is_empty()))
    };
    let codex = present(&["CODEX_SESSION_ID", "CODEX_THREAD_ID"]);
    let claude = present(&["CLAUDE_SESSION_ID", "CLAUDECODE"]);
    match (codex, claude) {
        (true, false) => "codex",
        (false, true) => "claude-code",
        _ => "cli",
    }
}

fn current_project() -> Option<String> {
    env::current_dir()
        .ok()
        .and_then(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .map(str::to_owned)
        })
        .filter(|name| check_metadata_text(name).is_ok())
}

pub(crate) fn mcp_metadata(params: &Value, protocol_version: &str) -> Result<ClientMetadata> {
    let client_info = &params["clientInfo"];
    let client_name = client_info["name"].as_str().unwrap_or("unknown");
    let product_version = client_info["version"].as_str().unwrap_or("unknown");
    check_metadata_text(client_name)?;
    check_metadata_text(product_version)?;
    let (product, display_name) = normalize_client(client_name);
    let session_name = session_environment(product, "NAME")
        .or_else(|| client_info["title"].as_str().map(str::to_owned));
    let session_id = session_environment(product, "ID");
    if let Some(value) = &session_name {
        check_metadata_text(value)?;
    }
    if let Some(value) = &session_id {
        check_metadata_text(value)?;
    }
    let host = env::var("HOSTNAME")
        .ok()
        .filter(|value| check_metadata_text(value).is_ok())
        .unwrap_or_else(|| "Mac".into());
    let project = current_project();
    let mut capabilities = client_info_capabilities(&params["capabilities"]);
    capabilities.sort();
    capabilities.dedup();
    Ok(ClientMetadata {
        product: product.into(),
        client_name: client_name.into(),
        display_name: display_name.into(),
        product_version: product_version.into(),
        protocol_version: protocol_version.into(),
        transport: "stdio".into(),
        session_id,
        session_name,
        host,
        project,
        pid: Some(process::id()),
        capabilities,
    })
}

pub(crate) fn normalize_client(name: &str) -> (&'static str, &'static str) {
    let normalized = name.to_ascii_lowercase().replace(['_', ' '], "-");
    if normalized.contains("codex") {
        ("codex", "Codex")
    } else if normalized.contains("claude") {
        ("claude-code", "Claude Code")
    } else {
        ("mcp", "MCP client")
    }
}

fn session_environment(product: &str, kind: &str) -> Option<String> {
    session_environment_with(product, kind, &|key| env::var(key).ok())
}

fn session_environment_with(
    product: &str,
    kind: &str,
    environment: &impl Fn(&str) -> Option<String>,
) -> Option<String> {
    let names: &[&str] = match (product, kind) {
        ("codex", "NAME") => &["CODEX_SESSION_NAME", "MCP_SESSION_NAME"],
        ("codex", "ID") => &["CODEX_SESSION_ID", "CODEX_THREAD_ID", "MCP_SESSION_ID"],
        ("claude-code", "NAME") => &["CLAUDE_SESSION_NAME", "MCP_SESSION_NAME"],
        ("claude-code", "ID") => &["CLAUDE_SESSION_ID", "MCP_SESSION_ID"],
        (_, "NAME") => &["MCP_SESSION_NAME"],
        _ => &["MCP_SESSION_ID"],
    };
    names
        .iter()
        .find_map(|key| environment(key).filter(|value| !value.trim().is_empty()))
}

fn client_info_capabilities(capabilities: &Value) -> Vec<String> {
    capabilities
        .as_object()
        .map(|value| value.keys().cloned().collect())
        .unwrap_or_default()
}

fn check_metadata_text(value: &str) -> Result<()> {
    if value.trim().is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        return Err(msg(
            "Invalid client metadata: use 1-256 characters without control characters",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn environment(key: &str) -> Option<String> {
        match key {
            "CODEX_THREAD_ID" => Some("thread-test".into()),
            "CODEX_SESSION_NAME" => Some("Fix the build".into()),
            "CLAUDE_SESSION_ID" => Some("claude-test".into()),
            "CLAUDE_SESSION_NAME" => Some("Review the build".into()),
            _ => None,
        }
    }

    #[test]
    fn cli_detects_nearest_agent_and_matching_session() {
        for (ancestors, product, display, session) in [
            (
                vec!["/bin/zsh", "/usr/local/bin/codex", "/usr/bin/claude"],
                "codex",
                "Codex",
                "thread-test",
            ),
            (
                vec!["/usr/local/bin/claude", "/usr/bin/codex"],
                "claude-code",
                "Claude Code",
                "claude-test",
            ),
        ] {
            let names = ancestors.into_iter().map(str::to_owned).collect::<Vec<_>>();
            let client = cli_metadata_with(None, None, None, &names, &environment).unwrap();
            assert_eq!(client.product, product);
            assert_eq!(client.display_name, display);
            assert_eq!(client.session_id.as_deref(), Some(session));
            assert_eq!(client.transport, "cli");
        }
    }

    #[test]
    fn cli_uses_allowlisted_environment_when_parent_is_unknown() {
        let client = cli_metadata_with(None, None, None, &[], &|key| {
            (key == "CODEX_THREAD_ID").then(|| "thread-test".into())
        })
        .unwrap();
        assert_eq!(client.display_name, "Codex");
        assert_eq!(client.session_id.as_deref(), Some("thread-test"));
        let unknown = cli_metadata_with(None, None, None, &[], &|_| None).unwrap();
        assert_eq!(unknown.display_name, "Keywarden CLI");
        assert_eq!(detect_cli_product(&[], &environment), "cli");
        assert_eq!(
            detect_cli_product(&["/tmp/not-codex".into()], &|_| None),
            "cli"
        );
    }

    #[test]
    fn cli_overrides_are_explicit_and_validated() {
        let client = cli_metadata_with(
            Some("Deploy bot"),
            Some("Build Mac"),
            Some("Release"),
            &[],
            &environment,
        )
        .unwrap();
        assert_eq!(client.display_name, "Deploy bot");
        assert_eq!(client.host, "Build Mac");
        assert_eq!(client.session_name.as_deref(), Some("Release"));
        assert!(cli_metadata_with(Some("bad\nlabel"), None, None, &[], &environment).is_err());
        assert!(cli_metadata_with(None, None, Some("bad\nsession"), &[], &environment).is_err());
    }
}
