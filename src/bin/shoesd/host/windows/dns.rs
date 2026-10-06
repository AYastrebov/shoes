//! DNS on Windows: the tunnel adapter's resolvers, and an NRPT rule for `.`.
//!
//! The adapter's resolvers alone leak. Windows' smart multi-homed name
//! resolution sends each query out of every interface in parallel and takes
//! the first answer, so the local resolver still sees every hostname -- the
//! leak a client's encrypted-DNS setting exists to prevent. A Name Resolution
//! Policy Table rule for the `.` namespace sends every name to the session's
//! resolvers and nowhere else; it is the mechanism Always On VPN uses.
//!
//! Through the `DnsClient` PowerShell module: NRPT's documented interface. The
//! registry keys behind it can be written directly, but that skips the
//! notification the cmdlets send the DNS client. The script is built only
//! from parsed `IpAddr`s and constants, so nothing a client typed reaches it.

use std::net::IpAddr;
use std::path::PathBuf;

/// Marks the rule as this daemon's, so revert removes exactly what apply
/// added and never someone else's policy.
const RULE_COMMENT: &str = "shoesd";

/// Set (non-empty `servers`) or clear (empty) the session's DNS on `adapter`.
///
/// Clearing is revert, and runs after the adapter has usually gone with the
/// session: the adapter half then has nothing to do and that is success, as
/// the trait requires. The NRPT half is what matters there, and it does not
/// depend on the adapter at all.
pub fn write(adapter: &str, servers: &[IpAddr]) -> std::io::Result<()> {
    run_powershell(&script(adapter, servers))
}

/// Drop cached answers.
pub fn flush() -> std::io::Result<()> {
    let ipconfig = system32().join("ipconfig.exe");
    let output = std::process::Command::new(&ipconfig)
        .arg("/flushdns")
        .output()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(std::io::Error::other(format!(
            "{} /flushdns failed ({})",
            ipconfig.display(),
            output.status
        )))
    }
}

/// The PowerShell that does it. Pure, for the tests.
///
/// A revert removes every rule of this daemon's. An apply never leaves a
/// moment without one: it runs on every network change -- twice, settled and
/// on the second look -- including the changes this daemon's own routes
/// trigger, and a remove-then-add would open a window each time in which
/// multi-homed resolution leaks lookups to every interface. So a rule that
/// already names these servers is kept as it is, and a changed one is
/// replaced by adding the new rule *before* removing the old.
fn script(adapter: &str, servers: &[IpAddr]) -> String {
    let mut script = String::from("$ErrorActionPreference = 'Stop'\n");
    script.push_str(&format!(
        "$ours = @(Get-DnsClientNrptRule | Where-Object {{ $_.Comment -eq '{RULE_COMMENT}' }})\n"
    ));
    let adapter = quote(adapter);
    if servers.is_empty() {
        script.push_str("$ours | Remove-DnsClientNrptRule -Force\n");
        // The adapter is normally gone by now; when it is not, put it back to
        // DHCP-or-nothing. A missing adapter is not an error.
        script.push_str(&format!(
            "if (Get-NetAdapter -Name {adapter} -ErrorAction SilentlyContinue) {{ \
             Set-DnsClientServerAddress -InterfaceAlias {adapter} -ResetServerAddresses }}\n"
        ));
    } else {
        let list = servers
            .iter()
            .map(|ip| format!("'{ip}'"))
            .collect::<Vec<_>>()
            .join(",");
        script.push_str(&format!("$want = @({list})\n"));
        script.push_str(&format!(
            "Set-DnsClientServerAddress -InterfaceAlias {adapter} -ServerAddresses $want\n"
        ));
        // A rule of ours for `.` naming exactly these servers, if there is one.
        script.push_str(
            "$keep = @($ours | Where-Object { $_.Namespace -contains '.' -and \
             -not (Compare-Object @($_.NameServers) $want) })\n",
        );
        script.push_str(&format!(
            "if ($keep.Count -eq 0) {{\n\
             \x20   Add-DnsClientNrptRule -Namespace '.' -NameServers $want -Comment '{RULE_COMMENT}'\n\
             \x20   $ours | Remove-DnsClientNrptRule -Force\n\
             }} else {{\n\
             \x20   $ours | Where-Object {{ $_.Name -ne $keep[0].Name }} | Remove-DnsClientNrptRule -Force\n\
             }}\n"
        ));
    }
    script
}

/// A PowerShell single-quoted literal. The adapter name is the daemon's own
/// constant, but quoting it properly costs nothing.
fn quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', "''"))
}

fn system32() -> PathBuf {
    let root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
    PathBuf::from(root).join("System32")
}

/// By absolute path, never from `PATH`, as the Unix arms run `ip` and `route`.
fn run_powershell(script: &str) -> std::io::Result<()> {
    let powershell = system32().join("WindowsPowerShell\\v1.0\\powershell.exe");
    let output = std::process::Command::new(&powershell)
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ])
        .output()?;
    if output.status.success() {
        return Ok(());
    }
    Err(std::io::Error::other(format!(
        "DNS configuration failed ({}): {}",
        output.status,
        String::from_utf8_lossy(&output.stderr).trim()
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ips(list: &[&str]) -> Vec<IpAddr> {
        list.iter().map(|s| s.parse().unwrap()).collect()
    }

    #[test]
    fn apply_sets_the_adapter_and_the_rule_for_every_name() {
        let script = script("shoesd", &ips(&["1.1.1.1", "1.0.0.1"]));

        assert!(
            script.contains("$want = @('1.1.1.1','1.0.0.1')"),
            "{script}"
        );
        assert!(
            script.contains(
                "Set-DnsClientServerAddress -InterfaceAlias 'shoesd' -ServerAddresses $want"
            ),
            "{script}"
        );
        assert!(
            script.contains(
                "Add-DnsClientNrptRule -Namespace '.' -NameServers $want -Comment 'shoesd'"
            ),
            "{script}"
        );
    }

    /// A re-apply never leaves a moment with no rule: when the rule changes,
    /// the new one is added before the old one is removed.
    #[test]
    fn apply_adds_the_new_rule_before_removing_the_old() {
        let script = script("shoesd", &ips(&["9.9.9.9"]));

        let add = script.find("Add-DnsClientNrptRule").expect("adds");
        let remove = script
            .find("$ours | Remove-DnsClientNrptRule")
            .expect("removes");
        assert!(add < remove, "{script}");
    }

    /// And when the rule already names these servers it is kept as it is --
    /// the common re-apply, which then touches NRPT not at all.
    #[test]
    fn apply_keeps_a_rule_that_already_names_these_servers() {
        let script = script("shoesd", &ips(&["9.9.9.9"]));

        assert!(
            script.contains("Compare-Object @($_.NameServers) $want"),
            "{script}"
        );
        assert!(script.contains("if ($keep.Count -eq 0)"), "{script}");
    }

    /// The script PowerShell's own parser accepts, for both shapes -- the
    /// string tests above cannot catch a brace out of place.
    #[test]
    fn both_scripts_parse() {
        for servers in [ips(&["1.1.1.1"]), Vec::new()] {
            let text = script("shoesd", &servers);
            let check = format!(
                "$e = $null; [System.Management.Automation.Language.Parser]::ParseInput({}, \
                 [ref]$null, [ref]$e) | Out-Null; if ($e.Count) {{ $e | ForEach-Object Message; exit 1 }}",
                quote(&text)
            );
            let output = std::process::Command::new(
                system32().join("WindowsPowerShell\\v1.0\\powershell.exe"),
            )
            .args(["-NoProfile", "-NonInteractive", "-Command", &check])
            .output()
            .expect("powershell runs");
            assert!(
                output.status.success(),
                "{text}\n{}",
                String::from_utf8_lossy(&output.stdout)
            );
        }
    }

    /// Revert removes only this daemon's rule and adds nothing.
    #[test]
    fn revert_removes_the_rule_and_adds_none() {
        let script = script("shoesd", &[]);

        assert!(script.contains("$_.Comment -eq 'shoesd'"), "{script}");
        assert!(!script.contains("Add-DnsClientNrptRule"), "{script}");
        assert!(script.contains("-ResetServerAddresses"), "{script}");
    }

    #[test]
    fn a_quote_in_the_adapter_name_cannot_escape_its_literal() {
        assert_eq!(quote("o'brien"), "'o''brien'");
    }

    /// Errors stop the script, so a failed rule is a failed apply -- and the
    /// plan then reverts -- rather than a session with DNS half set.
    #[test]
    fn the_script_stops_on_the_first_error() {
        assert!(script("shoesd", &[]).starts_with("$ErrorActionPreference = 'Stop'"));
    }
}
