use std::{
    env, fs,
    io::{BufReader, Read},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use psst::{EXTENSION_ID, EXTENSION_ORIGIN, NATIVE_HOST};
use serde::Serialize;
use serde_json::json;

use crate::error::{Error, Result};

const CONTAINER_ROOT: &str = "/opt/psst";
const CONTAINER_EXTENSION_CRX: &str = "/opt/psst/chrome-extension.crx";

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserStatus {
    browser_bridge: PathBuf,
    browser_bridge_present: bool,
    browser_extension_crx: PathBuf,
    browser_extension_crx_present: bool,
    container_native_host_manifest: PathBuf,
    container_native_host_manifest_present: bool,
    container_external_extension_manifest: PathBuf,
    container_external_extension_manifest_present: bool,
}

struct BrowserPaths {
    legacy_extension: PathBuf,
    legacy_native_host_manifests: Vec<PathBuf>,
    browser_bridge: PathBuf,
    browser_extension_crx: PathBuf,
    container_native_host_manifest: PathBuf,
    container_external_extension_manifest: PathBuf,
    legacy_config: PathBuf,
}

pub fn install() -> Result<()> {
    let paths = paths()?;

    remove_directory_if_exists(&paths.legacy_extension)?;
    for manifest in &paths.legacy_native_host_manifests {
        remove_file_if_exists(manifest)?;
    }
    remove_file_if_exists(&paths.legacy_config)?;

    let executable = env::current_exe()?.canonicalize()?;
    let browser_bridge_executable = browser_bridge_executable(&executable)?;
    let browser_extension_crx = browser_extension_crx(&executable)?;
    copy_executable_if_changed(&browser_bridge_executable, &paths.browser_bridge)?;
    copy_file_if_changed(&browser_extension_crx, &paths.browser_extension_crx, 0o644)?;

    let container_manifest = container_native_host_manifest()?;
    write_if_changed(
        paths.container_native_host_manifest.clone(),
        &container_manifest,
    )?;

    let external_extension_manifest = serde_json::to_vec_pretty(&json!({
        "external_crx": CONTAINER_EXTENSION_CRX,
        "external_version": env!("CARGO_PKG_VERSION"),
    }))?;
    write_if_changed(
        paths.container_external_extension_manifest.clone(),
        &external_extension_manifest,
    )?;

    Ok(())
}

pub fn status() -> Result<BrowserStatus> {
    let paths = paths()?;
    let container_native_host_manifest_present = paths.container_native_host_manifest.is_file();
    let container_external_extension_manifest_present =
        paths.container_external_extension_manifest.is_file();

    Ok(BrowserStatus {
        browser_bridge_present: paths.browser_bridge.is_file(),
        browser_extension_crx_present: paths.browser_extension_crx.is_file(),
        browser_bridge: paths.browser_bridge,
        browser_extension_crx: paths.browser_extension_crx,
        container_native_host_manifest: paths.container_native_host_manifest,
        container_native_host_manifest_present,
        container_external_extension_manifest: paths.container_external_extension_manifest,
        container_external_extension_manifest_present,
    })
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

fn container_native_host_manifest() -> Result<Vec<u8>> {
    Ok(serde_json::to_vec_pretty(&json!({
        "name": NATIVE_HOST,
        "description": "psst passkey native messaging host",
        "path": format!("{CONTAINER_ROOT}/browser-bridge"),
        "type": "stdio",
        "allowed_origins": [EXTENSION_ORIGIN],
    }))?)
}

fn remove_directory_if_exists(path: &Path) -> Result<()> {
    match fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn remove_file_if_exists(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn copy_executable_if_changed(source: &Path, destination: &Path) -> Result<()> {
    copy_file_if_changed(source, destination, 0o755)
}

fn copy_file_if_changed(source: &Path, destination: &Path, mode: u32) -> Result<()> {
    if files_equal(source, destination)? {
        return Ok(());
    }

    let parent = destination.parent().ok_or(Error::BrowserInstallPath)?;
    fs::create_dir_all(parent)?;
    let temporary = destination.with_extension(format!("tmp-{}", std::process::id()));
    let result = fs::copy(source, &temporary)
        .and_then(|_| fs::set_permissions(&temporary, fs::Permissions::from_mode(mode)))
        .and_then(|()| fs::rename(&temporary, destination));
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result?;
    Ok(())
}

fn browser_bridge_executable(executable: &Path) -> Result<PathBuf> {
    let configured = option_env!("PSST_BROWSER_BRIDGE_PATH")
        .filter(|path| !path.is_empty())
        .map(Path::new);

    resolve_browser_bridge_executable(executable, configured)
}

fn browser_extension_crx(executable: &Path) -> Result<PathBuf> {
    let configured = option_env!("PSST_BROWSER_EXTENSION_PATH")
        .filter(|path| !path.is_empty())
        .map(Path::new);

    resolve_browser_extension_crx(executable, configured)
}

fn resolve_browser_extension_crx(executable: &Path, configured: Option<&Path>) -> Result<PathBuf> {
    let browser_extension = configured
        .map(Path::to_path_buf)
        .unwrap_or_else(|| executable.with_file_name("psst-chrome-extension.crx"));
    if !browser_extension.is_file() {
        return Err(Error::BrowserExtensionUnavailable(browser_extension));
    }

    Ok(browser_extension.canonicalize()?)
}

fn resolve_browser_bridge_executable(
    executable: &Path,
    configured: Option<&Path>,
) -> Result<PathBuf> {
    let browser_bridge = configured
        .map(Path::to_path_buf)
        .unwrap_or_else(|| executable.with_file_name("psst-browser-bridge"));
    if !browser_bridge.is_file() {
        return Err(Error::BrowserBridgeUnavailable(browser_bridge));
    }

    Ok(browser_bridge.canonicalize()?)
}

fn files_equal(left: &Path, right: &Path) -> Result<bool> {
    let left_metadata = fs::metadata(left)?;
    let right_metadata = match fs::metadata(right) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    if left_metadata.len() != right_metadata.len() {
        return Ok(false);
    }

    let mut left = BufReader::new(fs::File::open(left)?);
    let mut right = BufReader::new(fs::File::open(right)?);
    let mut left_buffer = [0_u8; 64 * 1024];
    let mut right_buffer = [0_u8; 64 * 1024];
    loop {
        let left_length = left.read(&mut left_buffer)?;
        let right_length = right.read(&mut right_buffer)?;
        if left_length != right_length || left_buffer[..left_length] != right_buffer[..right_length]
        {
            return Ok(false);
        }
        if left_length == 0 {
            return Ok(true);
        }
    }
}

fn config_home() -> Result<PathBuf> {
    env::var_os("XDG_CONFIG_HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .map_or_else(|| Ok(home_dir()?.join(".config")), Ok)
}

fn data_home() -> Result<PathBuf> {
    env::var_os("XDG_DATA_HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .map_or_else(|| Ok(home_dir()?.join(".local/share")), Ok)
}

fn home_dir() -> Result<PathBuf> {
    env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .ok_or(Error::HomeDirectory)
}

fn paths() -> Result<BrowserPaths> {
    let data_home = data_home()?;
    let config_home = config_home()?;
    let legacy_native_host_manifests = ["google-chrome", "google-chrome-for-testing", "chromium"]
        .into_iter()
        .map(|browser| {
            config_home
                .join(browser)
                .join("NativeMessagingHosts")
                .join(format!("{NATIVE_HOST}.json"))
        })
        .collect();

    Ok(BrowserPaths {
        legacy_extension: data_home.join("psst/chrome-extension"),
        legacy_native_host_manifests,
        browser_bridge: data_home.join("psst/browser-bridge"),
        browser_extension_crx: data_home.join("psst/chrome-extension.crx"),
        container_native_host_manifest: data_home
            .join("psst/container-native-host")
            .join(format!("{NATIVE_HOST}.json")),
        container_external_extension_manifest: data_home
            .join("psst/container-external-extension")
            .join(format!("{EXTENSION_ID}.json")),
        legacy_config: config_home.join("psst/browser.json"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extension_manifest_has_the_native_messaging_boundary() {
        let manifest: serde_json::Value =
            serde_json::from_str(include_str!("../browser-extension/manifest.json")).unwrap();

        assert_eq!(manifest["manifest_version"], 3);
        assert_eq!(manifest["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(
            manifest["permissions"],
            json!(["nativeMessaging", "webAuthenticationProxy"])
        );
        assert_eq!(manifest["minimum_chrome_version"], "115");
        assert_eq!(manifest["content_scripts"][0]["world"], "ISOLATED");
        assert_eq!(manifest["content_scripts"][1]["world"], "MAIN");
    }

    #[test]
    fn container_extension_manifest_uses_the_packaged_extension_id() {
        assert_eq!(
            EXTENSION_ORIGIN,
            format!("chrome-extension://{EXTENSION_ID}/")
        );
    }

    #[test]
    fn legacy_installation_removal_is_idempotent() {
        let directory = tempfile::tempdir().unwrap();
        let extension = directory.path().join("chrome-extension");
        let manifest = directory.path().join("native-host.json");
        fs::create_dir(&extension).unwrap();
        fs::write(extension.join("manifest.json"), []).unwrap();
        fs::write(&manifest, []).unwrap();

        remove_directory_if_exists(&extension).unwrap();
        remove_file_if_exists(&manifest).unwrap();
        remove_directory_if_exists(&extension).unwrap();
        remove_file_if_exists(&manifest).unwrap();

        assert!(!extension.exists());
        assert!(!manifest.exists());
    }

    #[test]
    fn container_native_host_runs_the_browser_bridge_directly() {
        let manifest: serde_json::Value =
            serde_json::from_slice(&container_native_host_manifest().unwrap()).unwrap();

        assert_eq!(manifest["path"], "/opt/psst/browser-bridge");
    }

    #[test]
    fn browser_bridge_is_resolved_next_to_the_cli() {
        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("psst");
        let browser_bridge = directory.path().join("psst-browser-bridge");
        fs::write(&browser_bridge, []).unwrap();

        assert_eq!(
            resolve_browser_bridge_executable(&executable, None).unwrap(),
            browser_bridge.canonicalize().unwrap()
        );
    }

    #[test]
    fn browser_bridge_uses_the_configured_build_path() {
        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("bin/psst");
        let browser_bridge = directory.path().join("lib/psst/browser-bridge");
        fs::create_dir_all(browser_bridge.parent().unwrap()).unwrap();
        fs::write(&browser_bridge, []).unwrap();

        assert_eq!(
            resolve_browser_bridge_executable(&executable, Some(&browser_bridge)).unwrap(),
            browser_bridge.canonicalize().unwrap()
        );
    }

    #[test]
    fn browser_extension_uses_the_configured_build_path() {
        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("bin/psst");
        let browser_extension = directory.path().join("share/psst/extension.crx");
        fs::create_dir_all(browser_extension.parent().unwrap()).unwrap();
        fs::write(&browser_extension, []).unwrap();

        assert_eq!(
            resolve_browser_extension_crx(&executable, Some(&browser_extension)).unwrap(),
            browser_extension.canonicalize().unwrap()
        );
    }
}
