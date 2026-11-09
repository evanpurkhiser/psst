use std::{
    env, fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::error::{Error, Result};

pub const EXTENSION_ORIGIN: &str = "chrome-extension://mmehefpkhobgphfjkjlnebgbgfbmmmca/";
pub const NATIVE_HOST: &str = "com.evanpurkhiser.psst";

const MANIFEST: &str = include_str!("../browser-extension/manifest.json");
const BACKGROUND: &str = include_str!("../browser-extension/background.js");
const RELAY: &str = include_str!("../browser-extension/relay.js");
const BRIDGE: &str = include_str!("../browser-extension/bridge.js");
const NATIVE_HOST_PROXY: &str = include_str!("../browser-extension/native-host.py");
const CONTAINER_ROOT: &str = "/opt/psst";

#[derive(Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserConfig {
    pub allowed_peer_uids: Vec<u32>,
}

pub struct Installation {
    pub extension: PathBuf,
}

pub fn is_extension_origin(value: &str) -> bool {
    value == EXTENSION_ORIGIN || value == EXTENSION_ORIGIN.trim_end_matches('/')
}

pub fn install(allowed_peer_uids: &[u32]) -> Result<Installation> {
    let home = home_dir()?;
    let data_home = env::var_os("XDG_DATA_HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".local/share"));
    let config_home = env::var_os("XDG_CONFIG_HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".config"));
    let extension = data_home.join("psst/chrome-extension");

    write_if_changed(extension.join("manifest.json"), MANIFEST.as_bytes())?;
    write_if_changed(extension.join("background.js"), BACKGROUND.as_bytes())?;
    write_if_changed(extension.join("relay.js"), RELAY.as_bytes())?;
    write_if_changed(extension.join("bridge.js"), BRIDGE.as_bytes())?;

    let native_host_proxy = data_home.join("psst/native-host.py");
    write_executable_if_changed(&native_host_proxy, NATIVE_HOST_PROXY.as_bytes())?;

    let executable = env::current_exe()?.canonicalize()?;
    let native_manifest = serde_json::to_vec_pretty(&json!({
        "name": NATIVE_HOST,
        "description": "PSST passkey native messaging host",
        "path": executable,
        "type": "stdio",
        "allowed_origins": [EXTENSION_ORIGIN],
    }))?;
    for browser in ["google-chrome", "google-chrome-for-testing", "chromium"] {
        write_if_changed(
            config_home
                .join(browser)
                .join("NativeMessagingHosts")
                .join(format!("{NATIVE_HOST}.json")),
            &native_manifest,
        )?;
    }

    let container_manifest = serde_json::to_vec_pretty(&json!({
        "name": NATIVE_HOST,
        "description": "PSST passkey native messaging host",
        "path": format!("{CONTAINER_ROOT}/native-host.py"),
        "type": "stdio",
        "allowed_origins": [EXTENSION_ORIGIN],
    }))?;
    write_if_changed(
        data_home
            .join("psst/container-native-host")
            .join(format!("{NATIVE_HOST}.json")),
        &container_manifest,
    )?;

    if !allowed_peer_uids.is_empty() {
        let config = BrowserConfig {
            allowed_peer_uids: allowed_peer_uids.to_vec(),
        };
        write_if_changed(
            config_home.join("psst/browser.json"),
            &serde_json::to_vec_pretty(&config)?,
        )?;
    }

    Ok(Installation { extension })
}

pub fn config() -> Result<BrowserConfig> {
    let path = config_home()?.join("psst/browser.json");
    let contents = match fs::read(path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(BrowserConfig::default());
        }
        Err(error) => return Err(error.into()),
    };

    Ok(serde_json::from_slice(&contents)?)
}

pub fn socket_path() -> Result<PathBuf> {
    let runtime = env::var_os("XDG_RUNTIME_DIR").ok_or(Error::RuntimeDirectory)?;
    Ok(PathBuf::from(runtime).join("psst-browser/bridge.sock"))
}

fn write_if_changed(path: PathBuf, contents: &[u8]) -> Result<()> {
    if fs::read(&path).is_ok_and(|current| current == contents) {
        return Ok(());
    }
    let parent = path.parent().ok_or(Error::BrowserInstallPath)?;
    fs::create_dir_all(parent)?;
    fs::write(path, contents)?;
    Ok(())
}

fn write_executable_if_changed(path: &Path, contents: &[u8]) -> Result<()> {
    write_if_changed(path.to_path_buf(), contents)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o755))?;
    Ok(())
}

fn config_home() -> Result<PathBuf> {
    env::var_os("XDG_CONFIG_HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .map_or_else(|| Ok(home_dir()?.join(".config")), Ok)
}

fn home_dir() -> Result<PathBuf> {
    env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .ok_or(Error::HomeDirectory)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_extension_manifest_has_the_native_messaging_boundary() {
        let manifest: serde_json::Value = serde_json::from_str(MANIFEST).unwrap();

        assert_eq!(manifest["manifest_version"], 3);
        assert_eq!(manifest["permissions"], json!(["nativeMessaging"]));
        assert_eq!(manifest["content_scripts"][0]["world"], "ISOLATED");
        assert_eq!(manifest["content_scripts"][1]["world"], "MAIN");
    }

    #[test]
    fn browser_config_defaults_to_no_container_peers() {
        assert!(BrowserConfig::default().allowed_peer_uids.is_empty());
    }
}
