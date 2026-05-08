use anyhow::{bail, Context, Result};
use std::path::Path;
use std::process::Command;

pub enum ElevationOutcome {
    Continue,
    Relaunched,
}

pub(crate) const LINUX_GUI_ENV_KEYS: &[&str] = &[
    "DISPLAY",
    "XAUTHORITY",
    "WAYLAND_DISPLAY",
    "WAYLAND_SOCKET",
    "XDG_RUNTIME_DIR",
    "DBUS_SESSION_BUS_ADDRESS",
];

pub(crate) fn linux_gui_env_from<F>(get: F) -> Vec<(&'static str, String)>
where
    F: Fn(&str) -> Option<String>,
{
    LINUX_GUI_ENV_KEYS
        .iter()
        .filter_map(|key| get(key).map(|val| (*key, val)))
        .collect()
}

#[allow(dead_code)]
pub(crate) fn ps_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

#[allow(dead_code)]
pub(crate) fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

pub fn ensure_elevated(binary_name: &str) -> Result<ElevationOutcome> {
    if is_elevated() {
        return Ok(ElevationOutcome::Continue);
    }

    let exe = std::env::current_exe().context("resolve current executable path")?;
    let args: Vec<String> = std::env::args().skip(1).collect();

    if try_relaunch_elevated(&exe, &args) {
        eprintln!("{binary_name}: requesting elevated privileges...");
        return Ok(ElevationOutcome::Relaunched);
    }

    bail!(
        "{binary_name} requires administrator/root privileges.\n\
        Why: it must create a TUN network interface and modify system routing/NAT.\n\
        Run as root/admin (sudo on Linux/macOS, Administrator on Windows).\n\
        Source code: {}",
        source_url()
    );
}

fn source_url() -> &'static str {
    option_env!("CARGO_PKG_REPOSITORY").unwrap_or("https://github.com/ivbeck/obfs")
}

fn try_relaunch_elevated(exe: &Path, args: &[String]) -> bool {
    #[cfg(target_os = "windows")]
    {
        return relaunch_windows(exe, args);
    }
    #[cfg(target_os = "macos")]
    {
        return relaunch_macos(exe, args);
    }
    #[cfg(target_os = "linux")]
    {
        let gui_env = linux_gui_env();
        let mut pkexec = Command::new("pkexec");
        if !gui_env.is_empty() {
            pkexec.arg("env");
            for (k, v) in &gui_env {
                pkexec.arg(format!("{k}={v}"));
            }
        }
        if pkexec.arg(exe).args(args).spawn().is_ok() {
            return true;
        }
        let mut sudo = Command::new("sudo");
        if !gui_env.is_empty() {
            sudo.arg("-E");
        }
        if sudo.arg(exe).args(args).spawn().is_ok() {
            return true;
        }
        false
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        let _ = (exe, args);
        false
    }
}

#[cfg(target_os = "windows")]
fn relaunch_windows(exe: &Path, args: &[String]) -> bool {
    let exe_escaped = ps_quote(&exe.to_string_lossy());
    let arg_list = args
        .iter()
        .map(|a| ps_quote(a))
        .collect::<Vec<_>>()
        .join(", ");
    let command =
        format!("Start-Process -FilePath {exe_escaped} -ArgumentList @({arg_list}) -Verb RunAs");
    Command::new("powershell")
        .args(["-NoProfile", "-Command", &command])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(target_os = "macos")]
fn relaunch_macos(exe: &Path, args: &[String]) -> bool {
    let cmd = std::iter::once(exe.to_string_lossy().to_string())
        .chain(args.iter().cloned())
        .map(|p| shell_quote(&p))
        .collect::<Vec<_>>()
        .join(" ");
    let applescript = format!(
        "do shell script \"{cmd} >/dev/null 2>&1 &\" with administrator privileges",
        cmd = cmd.replace('\\', "\\\\").replace('"', "\\\"")
    );
    Command::new("osascript")
        .args(["-e", &applescript])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(target_os = "linux")]
fn linux_gui_env() -> Vec<(&'static str, String)> {
    linux_gui_env_from(|k| std::env::var(k).ok())
}

fn is_elevated() -> bool {
    #[cfg(unix)]
    {
        // SAFETY: libc::geteuid is thread-safe and has no preconditions.
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(target_os = "windows")]
    {
        let out = Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                "[bool]([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)",
            ])
            .output();
        return out
            .ok()
            .map(|o| {
                String::from_utf8_lossy(&o.stdout)
                    .trim()
                    .eq_ignore_ascii_case("true")
            })
            .unwrap_or(false);
    }
    #[cfg(not(any(unix, target_os = "windows")))]
    {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    #[cfg(unix)]
    fn is_elevated_false_in_ci() {
        // CI never runs as root. If you see this fail locally, you're root — go fix that.
        assert!(!is_elevated());
    }

    #[test]
    fn linux_gui_env_filters_missing() {
        let env: HashMap<&str, String> = HashMap::new();
        let out = linux_gui_env_from(|k| env.get(k).cloned());
        assert!(out.is_empty());
    }

    #[test]
    fn linux_gui_env_includes_present() {
        let mut env: HashMap<&str, String> = HashMap::new();
        env.insert("DISPLAY", ":0".into());
        let out = linux_gui_env_from(|k| env.get(k).cloned());
        assert_eq!(out, vec![("DISPLAY", ":0".to_owned())]);
    }

    #[test]
    fn linux_gui_env_preserves_order() {
        let mut env: HashMap<&str, String> = HashMap::new();
        env.insert("DISPLAY", ":0".into());
        env.insert("WAYLAND_DISPLAY", "wayland-0".into());
        env.insert("DBUS_SESSION_BUS_ADDRESS", "unix:path=/run/dbus".into());
        let out = linux_gui_env_from(|k| env.get(k).cloned());
        // Order must follow LINUX_GUI_ENV_KEYS, not insertion order.
        let keys: Vec<&str> = out.iter().map(|(k, _)| *k).collect();
        assert_eq!(
            keys,
            vec!["DISPLAY", "WAYLAND_DISPLAY", "DBUS_SESSION_BUS_ADDRESS"]
        );
    }

    #[test]
    fn ps_quote_simple() {
        assert_eq!(ps_quote("foo"), "'foo'");
    }

    #[test]
    fn ps_quote_with_apostrophe_doubles() {
        // PowerShell single-quote escape: '' inside a single-quoted string.
        assert_eq!(ps_quote("it's"), "'it''s'");
    }

    #[test]
    fn shell_quote_simple() {
        assert_eq!(shell_quote("foo"), "'foo'");
    }

    #[test]
    fn shell_quote_with_apostrophe() {
        // Standard POSIX trick: close, escaped quote, reopen.
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
    }

    #[test]
    fn shell_quote_with_backslash_and_quote() {
        // Backslash gets through untouched; only the apostrophe needs escaping.
        assert_eq!(shell_quote(r"a\b'c"), r"'a\b'\''c'");
    }

    #[test]
    #[ignore]
    fn ensure_elevated_in_ci_relaunches_or_errors() {
        // Host-dependent (pkexec/sudo behavior).  Marked ignore by default.
        let _ = ensure_elevated("test-binary");
    }
}
