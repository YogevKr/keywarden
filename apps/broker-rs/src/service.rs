use crate::{env, msg, Result};
use std::path::PathBuf;
use tokio::process::Command;

pub async fn run(args: &[String]) -> Result<()> {
    let user_dir = PathBuf::from(env::var("HOME").map_err(|_| msg("Missing home directory"))?);
    let uid = Command::new("/usr/bin/id").arg("-u").output().await?;
    let domain = format!("gui/{}", String::from_utf8_lossy(&uid.stdout).trim());
    let label = "ai.sawmills.keywarden";
    if args.first().map(String::as_str) == Some("stop") {
        let status = Command::new("/bin/launchctl")
            .args(["bootout", &format!("{domain}/{label}")])
            .status()
            .await?;
        if !status.success() {
            return Err(msg("Could not stop the Keywarden service"));
        }
        println!("Keywarden stopped. All sessions ended.");
        return Ok(());
    }
    let target = format!("{domain}/{label}");
    if Command::new("/bin/launchctl")
        .args(["print", &target])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await?
        .success()
    {
        println!("Keywarden is already registered. Run keywarden status.");
        return Ok(());
    }
    let exe = env::current_exe()?;
    let logs = user_dir.join("Library/Logs/Keywarden");
    std::fs::create_dir_all(&logs)?;
    let agents = user_dir.join("Library/LaunchAgents");
    std::fs::create_dir_all(&agents)?;
    let path = agents.join(format!("{label}.plist"));
    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>{label}</string>
<key>ProgramArguments</key><array><string>{}</string><string>serve</string><string>--opgate</string></array>
<key>EnvironmentVariables</key><dict><key>PATH</key><string>/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin</string><key>HOME</key><string>{}</string></dict>
<key>RunAtLoad</key><true/><key>KeepAlive</key><true/><key>ThrottleInterval</key><integer>30</integer>
<key>StandardOutPath</key><string>{}</string><key>StandardErrorPath</key><string>{}</string>
</dict></plist>
"#,
        xml(&exe.to_string_lossy()),
        xml(&user_dir.to_string_lossy()),
        xml(&logs.join("broker.log").to_string_lossy()),
        xml(&logs.join("broker-error.log").to_string_lossy())
    );
    if path.exists() && std::fs::read_to_string(&path)? != plist {
        return Err(msg(
            "Existing service configuration differs. Review it before replacing it.",
        ));
    }
    std::fs::write(&path, plist)?;
    let status = Command::new("/bin/launchctl")
        .args(["bootstrap", &domain])
        .arg(path)
        .status()
        .await?;
    if !status.success() {
        return Err(msg("Could not start the Keywarden service"));
    }
    println!("Keywarden started. Run keywarden status.");
    Ok(())
}

fn xml(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
