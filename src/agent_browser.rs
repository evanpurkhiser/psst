use std::{
    env,
    ffi::OsStr,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use serde::Serialize;
use serde_json::{Value, json};

use crate::error::{Error, Result};

const PLUGIN_NAME: &str = "psst";

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentBrowserStatus {
    config: PathBuf,
    plugin_present: bool,
    configured: bool,
}

pub fn install(config: Option<&Path>, force: bool) -> Result<()> {
    let path = config_path(config)?;
    let mut value = read_config(&path)?;
    let plugins = plugins(&mut value, &path)?;
    let expected = plugin_config();

    if let Some(current) = plugins
        .iter_mut()
        .find(|plugin| plugin["name"] == PLUGIN_NAME)
    {
        if *current == expected {
            return Ok(());
        }
        if !force {
            return Err(Error::IntegrationConflict(path));
        }
        *current = expected;
    } else {
        plugins.push(expected);
    }

    write_config(&path, &value)
}

pub fn status(config: Option<&Path>) -> Result<AgentBrowserStatus> {
    let path = config_path(config)?;
    let mut value = read_config(&path)?;
    let plugins = plugins(&mut value, &path)?;

    Ok(AgentBrowserStatus {
        config: path,
        plugin_present: plugins.iter().any(|plugin| plugin["name"] == PLUGIN_NAME),
        configured: plugins.iter().any(|plugin| *plugin == plugin_config()),
    })
}

fn plugin_config() -> Value {
    json!({
        "name": PLUGIN_NAME,
        "command": "psst",
        "args": ["agent-browser-plugin"],
        "capabilities": ["credential.read"],
    })
}

fn config_path(config: Option<&Path>) -> Result<PathBuf> {
    if let Some(config) = config {
        return Ok(config.to_path_buf());
    }
    if let Some(config) = env::var_os("AGENT_BROWSER_CONFIG").filter(|value| !value.is_empty()) {
        return Ok(PathBuf::from(config));
    }

    let home = env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .ok_or(Error::HomeDirectory)?;
    Ok(home.join(".agent-browser/config.json"))
}

fn read_config(path: &Path) -> Result<Value> {
    match fs::read(path) {
        Ok(contents) => {
            let value: Value = serde_json::from_slice(&contents)?;
            if value.is_object() {
                Ok(value)
            } else {
                Err(Error::IntegrationConfig(path.to_path_buf()))
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(json!({})),
        Err(error) => Err(error.into()),
    }
}

fn plugins<'a>(value: &'a mut Value, path: &Path) -> Result<&'a mut Vec<Value>> {
    let object = value
        .as_object_mut()
        .ok_or_else(|| Error::IntegrationConfig(path.to_path_buf()))?;
    let plugins = object
        .entry("plugins")
        .or_insert_with(|| Value::Array(Vec::new()));
    plugins
        .as_array_mut()
        .ok_or_else(|| Error::IntegrationConfig(path.to_path_buf()))
}

fn write_config(path: &Path, value: &Value) -> Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| parent.as_os_str() != OsStr::new(""))
    {
        fs::create_dir_all(parent)?;
    }

    let mut contents = serde_json::to_vec_pretty(value)?;
    contents.push(b'\n');
    let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
    let result = fs::write(&temporary, contents)
        .and_then(|()| fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600)))
        .and_then(|()| fs::rename(&temporary, path));
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn installs_without_replacing_other_configuration() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.json");
        fs::write(
            &path,
            br#"{"cdp":"http://127.0.0.1:9222","plugins":[{"name":"other"}]}"#,
        )
        .unwrap();

        install(Some(&path), false).unwrap();

        let value: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(value["cdp"], "http://127.0.0.1:9222");
        assert_eq!(value["plugins"][0]["name"], "other");
        assert_eq!(value["plugins"][1], plugin_config());
    }

    #[test]
    fn repeated_installation_is_idempotent() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.json");

        install(Some(&path), false).unwrap();
        install(Some(&path), false).unwrap();

        let value: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(value["plugins"].as_array().unwrap().len(), 1);
        let status = status(Some(&path)).unwrap();
        assert!(status.plugin_present);
        assert!(status.configured);
    }

    #[test]
    fn conflicting_plugin_requires_force() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.json");
        fs::write(&path, br#"{"plugins":[{"name":"psst","command":"other"}]}"#).unwrap();

        assert!(matches!(
            install(Some(&path), false),
            Err(Error::IntegrationConflict(_))
        ));
        let current = status(Some(&path)).unwrap();
        assert!(current.plugin_present);
        assert!(!current.configured);

        install(Some(&path), true).unwrap();
        assert!(status(Some(&path)).unwrap().configured);
    }
}
