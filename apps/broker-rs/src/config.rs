//! Local deployment references only. Credentials remain in 1Password.
use crate::{msg, Result};
use serde::Deserialize;

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct LocalConfig {
    pub relay_url: Option<String>,
    pub push_vault: Option<String>,
    pub push_item: Option<String>,
}

pub(crate) fn load() -> Result<LocalConfig> {
    let Some(home) = std::env::var_os("HOME") else {
        return Ok(LocalConfig::default());
    };
    let file = std::path::PathBuf::from(home).join(".config/keywarden/config.json");
    match std::fs::read(file) {
        Ok(bytes) => {
            serde_json::from_slice(&bytes).map_err(|_| msg("Invalid local Keywarden configuration"))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(LocalConfig::default()),
        Err(_) => Err(msg("Could not read local Keywarden configuration")),
    }
}
