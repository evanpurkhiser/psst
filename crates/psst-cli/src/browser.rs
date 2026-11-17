use std::{
    env, fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use serde::Serialize;
use serde_json::json;

use crate::{
    daemon::browser_protocol::EXTENSION_ID,
    error::{Error, Result},
};

const CONTAINER_EXTENSION_CRX: &str = "/opt/psst/chrome-extension.crx";

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserStatus {
    browser_extension_crx: PathBuf,
    browser_extension_crx_present: bool,
    container_external_extension_manifest: PathBuf,
    container_external_extension_manifest_present: bool,
}

struct BrowserPaths {
    browser_extension_crx: PathBuf,
    container_external_extension_manifest: PathBuf,
}

pub fn install() -> Result<()> {
    let paths = paths()?;
    let executable = env::current_exe()?.canonicalize()?;
    let browser_extension_crx = browser_extension_crx(&executable)?;
    copy_file(&browser_extension_crx, &paths.browser_extension_crx)?;

    let manifest = serde_json::to_vec_pretty(&json!({
        "external_crx": CONTAINER_EXTENSION_CRX,
        "external_version": env!("CARGO_PKG_VERSION"),
    }))?;
    write_file(paths.container_external_extension_manifest, &manifest)?;
    Ok(())
}

pub fn status() -> Result<BrowserStatus> {
    let paths = paths()?;
    Ok(BrowserStatus {
        browser_extension_crx_present: paths.browser_extension_crx.is_file(),
        container_external_extension_manifest_present: paths
            .container_external_extension_manifest
            .is_file(),
        browser_extension_crx: paths.browser_extension_crx,
        container_external_extension_manifest: paths.container_external_extension_manifest,
    })
}

fn write_file(path: PathBuf, contents: &[u8]) -> Result<()> {
    let parent = path.parent().ok_or(Error::BrowserInstallPath)?;
    fs::create_dir_all(parent)?;
    fs::write(path, contents)?;
    Ok(())
}

fn copy_file(source: &Path, destination: &Path) -> Result<()> {
    let parent = destination.parent().ok_or(Error::BrowserInstallPath)?;
    fs::create_dir_all(parent)?;
    let temporary = destination.with_extension(format!("tmp-{}", std::process::id()));
    let result = fs::copy(source, &temporary)
        .and_then(|_| fs::set_permissions(&temporary, fs::Permissions::from_mode(0o644)))
        .and_then(|()| fs::rename(&temporary, destination));
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result?;
    Ok(())
}

fn browser_extension_crx(executable: &Path) -> Result<PathBuf> {
    let configured = option_env!("PSST_BROWSER_EXTENSION_PATH")
        .filter(|path| !path.is_empty())
        .map(Path::new);
    let browser_extension = configured
        .map(Path::to_path_buf)
        .unwrap_or_else(|| executable.with_file_name("psst-chrome-extension.crx"));
    if !browser_extension.is_file() {
        return Err(Error::BrowserExtensionUnavailable(browser_extension));
    }

    Ok(browser_extension.canonicalize()?)
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
    Ok(BrowserPaths {
        browser_extension_crx: data_home.join("psst/chrome-extension.crx"),
        container_external_extension_manifest: data_home
            .join("psst/container-external-extension")
            .join(format!("{EXTENSION_ID}.json")),
    })
}
