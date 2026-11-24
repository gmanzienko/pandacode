//! A Linux AppImage starts PandaCode with its own libraries and runtimes on the search paths
//! (`LD_LIBRARY_PATH`, `PYTHONHOME`, `GIO_*`, `GTK_*`, `XDG_DATA_DIRS`, `PATH`…), all pointing
//! into the mounted image. External tools must not inherit them: the system `/usr/bin/env`,
//! `curl` or `python3` then load the bundled copies and fail. Every spawn of an external
//! process applies `sanitize`, which drops those entries and is a no-op outside an AppImage.

use std::ffi::{OsStr, OsString};
use std::path::Path;

/// Variables the AppImage runtime sets to describe itself.
const APPIMAGE_MARKERS: [&str; 4] = ["APPDIR", "APPIMAGE", "ARGV0", "OWD"];

/// Changes that undo the AppImage environment: `(name, Some(value))` sets, `(name, None)`
/// removes. Empty unless both `APPIMAGE` and an absolute `APPDIR` are present.
fn appimage_overrides(vars: &[(OsString, OsString)]) -> Vec<(OsString, Option<OsString>)> {
    let get = |name: &str| vars.iter().find(|(key, _)| key == name).map(|(_, value)| value);
    let (Some(_), Some(appdir)) = (get("APPIMAGE"), get("APPDIR")) else {
        return Vec::new();
    };
    let appdir = Path::new(appdir);
    if !appdir.is_absolute() || appdir.parent().is_none() {
        return Vec::new();
    }
    let inside = |entry: &OsStr| Path::new(entry).starts_with(appdir);
    vars.iter()
        .filter_map(|(key, value)| {
            if APPIMAGE_MARKERS.iter().any(|marker| key == marker) {
                return Some((key.clone(), None));
            }
            let entries: Vec<_> = std::env::split_paths(value).collect();
            if !entries.iter().any(|entry| inside(entry.as_os_str())) {
                return None;
            }
            let kept: Vec<_> = entries
                .into_iter()
                .filter(|entry| !entry.as_os_str().is_empty() && !inside(entry.as_os_str()))
                .collect();
            let joined = (!kept.is_empty()).then(|| std::env::join_paths(kept).ok()).flatten();
            Some((key.clone(), joined))
        })
        .collect()
}

pub(crate) trait EnvTarget {
    fn set_var(&mut self, key: &OsStr, value: &OsStr);
    fn remove_var(&mut self, key: &OsStr);
    /// The value the child will see for `key`: the latest override (`None` after a
    /// removal), else the value it inherits from this process.
    fn effective_var(&self, key: &OsStr) -> Option<OsString>;
}

/// Environment names are case-insensitive on Windows and exact elsewhere.
#[cfg(windows)]
fn same_env_key(a: &OsStr, b: &OsStr) -> bool {
    a == b || a.to_str().zip(b.to_str()).is_some_and(|(x, y)| x.eq_ignore_ascii_case(y))
}

#[cfg(not(windows))]
fn same_env_key(a: &OsStr, b: &OsStr) -> bool {
    a == b
}

impl EnvTarget for std::process::Command {
    fn set_var(&mut self, key: &OsStr, value: &OsStr) {
        self.env(key, value);
    }
    fn remove_var(&mut self, key: &OsStr) {
        self.env_remove(key);
    }
    fn effective_var(&self, key: &OsStr) -> Option<OsString> {
        match self.get_envs().filter(|(name, _)| same_env_key(name, key)).last() {
            Some((_, value)) => value.map(OsStr::to_os_string),
            None => std::env::var_os(key),
        }
    }
}

impl EnvTarget for tokio::process::Command {
    fn set_var(&mut self, key: &OsStr, value: &OsStr) {
        self.env(key, value);
    }
    fn remove_var(&mut self, key: &OsStr) {
        self.env_remove(key);
    }
    fn effective_var(&self, key: &OsStr) -> Option<OsString> {
        self.as_std().effective_var(key)
    }
}

impl EnvTarget for portable_pty::CommandBuilder {
    fn set_var(&mut self, key: &OsStr, value: &OsStr) {
        self.env(key, value);
    }
    fn remove_var(&mut self, key: &OsStr) {
        self.env_remove(key);
    }
    /// The builder starts from this process's environment, so its own map is complete.
    fn effective_var(&self, key: &OsStr) -> Option<OsString> {
        self.get_env(key).map(OsStr::to_os_string)
    }
}

/// Removes this process's AppImage environment from a command about to start an external
/// tool. Does nothing on macOS and Windows, or on Linux outside an AppImage.
pub(crate) fn sanitize(command: &mut impl EnvTarget) {
    if !cfg!(target_os = "linux") {
        return;
    }
    let vars: Vec<_> = std::env::vars_os().collect();
    for (key, value) in appimage_overrides(&vars) {
        match value {
            Some(value) => command.set_var(&key, &value),
            None => command.remove_var(&key),
        }
    }
}

#[cfg(test)]
mod effective_var_tests {
    use super::*;

    /// A name no real environment carries, so the inherited value is known to be absent.
    const KEY: &str = "PANDACODE_CHILD_ENV_FIXTURE_7F3A";

    #[test]
    fn std_and_tokio_commands_report_the_latest_override() {
        let key = OsStr::new(KEY);
        let mut command = std::process::Command::new("fixture");
        assert_eq!(command.effective_var(key), None);
        command.set_var(key, OsStr::new("first"));
        command.set_var(key, OsStr::new("second"));
        assert_eq!(command.effective_var(key), Some(OsString::from("second")));
        command.remove_var(key);
        assert_eq!(command.effective_var(key), None);
        let mut command = tokio::process::Command::new("fixture");
        command.set_var(key, OsStr::new("   "));
        assert_eq!(command.effective_var(key), Some(OsString::from("   ")));
    }

    #[test]
    fn std_commands_fall_back_to_the_inherited_value() {
        let command = std::process::Command::new("fixture");
        assert_eq!(command.effective_var(OsStr::new("PATH")), std::env::var_os("PATH"));
    }

    #[cfg(windows)]
    #[test]
    fn windows_names_match_case_insensitively() {
        let mut command = std::process::Command::new("fixture");
        command.set_var(OsStr::new(&KEY.to_ascii_lowercase()), OsStr::new("lower"));
        assert_eq!(command.effective_var(OsStr::new(KEY)), Some(OsString::from("lower")));
        assert!(same_env_key(OsStr::new("Path"), OsStr::new("PATH")));
    }

    #[test]
    fn pty_builders_report_their_own_environment() {
        let key = OsStr::new(KEY);
        let mut command = portable_pty::CommandBuilder::new("fixture");
        assert_eq!(command.effective_var(key), None);
        command.set_var(key, OsStr::new("value"));
        assert_eq!(command.effective_var(key), Some(OsString::from("value")));
        command.remove_var(key);
        assert_eq!(command.effective_var(key), None);
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn vars(pairs: &[(&str, &str)]) -> Vec<(OsString, OsString)> {
        pairs.iter().map(|(key, value)| (key.into(), value.into())).collect()
    }

    fn overrides(pairs: &[(&str, &str)]) -> Vec<(String, Option<String>)> {
        appimage_overrides(&vars(pairs))
            .into_iter()
            .map(|(key, value)| {
                (key.into_string().unwrap(), value.map(|value| value.into_string().unwrap()))
            })
            .collect()
    }

    #[test]
    fn appimage_entries_are_removed_and_the_rest_is_kept() {
        let mount = "/tmp/.mount_pandacjIIGkD";
        let found = overrides(&[
            ("APPIMAGE", "/home/me/.local/bin/pandacode"),
            ("APPDIR", mount),
            ("ARGV0", "pandacode"),
            ("OWD", "/home/me"),
            ("PATH", "/tmp/.mount_pandacjIIGkD/usr/bin:/home/me/.local/bin:/usr/bin"),
            ("LD_LIBRARY_PATH", "/tmp/.mount_pandacjIIGkD/usr/lib:/tmp/.mount_pandacjIIGkD/lib"),
            ("PYTHONHOME", "/tmp/.mount_pandacjIIGkD/usr"),
            ("GDK_PIXBUF_MODULE_FILE", "/tmp/.mount_pandacjIIGkD/usr/lib/loaders.cache"),
            ("XDG_DATA_DIRS", "/tmp/.mount_pandacjIIGkD/usr/share:/usr/local/share:/usr/share"),
            // A sibling mount sharing the prefix is not inside APPDIR.
            ("OTHER", "/tmp/.mount_pandacjIIGkDx/lib"),
            ("HOME", "/home/me"),
        ]);
        assert_eq!(
            found,
            [
                ("APPIMAGE".into(), None),
                ("APPDIR".into(), None),
                ("ARGV0".into(), None),
                ("OWD".into(), None),
                ("PATH".into(), Some("/home/me/.local/bin:/usr/bin".into())),
                ("LD_LIBRARY_PATH".into(), None),
                ("PYTHONHOME".into(), None),
                ("GDK_PIXBUF_MODULE_FILE".into(), None),
                ("XDG_DATA_DIRS".into(), Some("/usr/local/share:/usr/share".into())),
            ]
        );
    }

    #[test]
    fn nothing_changes_outside_an_appimage() {
        let path = ("PATH", "/tmp/.mount_x/usr/bin:/usr/bin");
        assert!(overrides(&[path, ("HOME", "/home/me")]).is_empty());
        assert!(overrides(&[path, ("APPDIR", "/tmp/.mount_x")]).is_empty());
        assert!(overrides(&[path, ("APPIMAGE", "/a"), ("APPDIR", "relative")]).is_empty());
        assert!(overrides(&[path, ("APPIMAGE", "/a"), ("APPDIR", "/")]).is_empty());
    }
}
