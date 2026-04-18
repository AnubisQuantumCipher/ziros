use crate::types::{
    AgentBrowserEvalReportV1, AgentBrowserEvalRequestV1, AgentBrowserKindV1,
    AgentBrowserOpenReportV1, AgentBrowserOpenRequestV1, AgentBrowserStatusReportV1,
};
use serde_json::Value;
use std::io::Write;
use std::process::{Command, Stdio};
use zkf_command_surface::now_rfc3339;

const BROWSER_STATUS_SCHEMA: &str = "ziros-agent-browser-status-v1";
const BROWSER_OPEN_SCHEMA: &str = "ziros-agent-browser-open-v1";
const BROWSER_EVAL_SCHEMA: &str = "ziros-agent-browser-eval-v1";
const DEFAULT_WAIT_MILLIS: u64 = 1_000;

pub fn browser_status() -> Result<AgentBrowserStatusReportV1, String> {
    #[cfg(target_os = "macos")]
    {
        let safari_installed = application_installed("Safari");
        let chrome_installed = application_installed("Google Chrome");
        let safari_running = process_running("Safari");
        let chrome_running = process_running("Google Chrome");
        let preferred_automation_browser = if chrome_installed {
            Some(AgentBrowserKindV1::Chrome)
        } else if safari_installed {
            Some(AgentBrowserKindV1::Safari)
        } else {
            None
        };
        let mut notes = vec![
            "GUI browser automation is macOS-only and uses AppleScript against Safari or Google Chrome."
                .to_string(),
            "Use 'ziros agent web fetch' first when a deterministic official-web fetch is sufficient."
                .to_string(),
        ];
        if safari_installed {
            notes.push(
                "Safari JavaScript automation may require enabling 'Allow JavaScript from Apple Events'."
                    .to_string(),
            );
        }
        if chrome_installed {
            notes.push(
                "Google Chrome automation may prompt for macOS Automation permission on first use."
                    .to_string(),
            );
        }
        Ok(AgentBrowserStatusReportV1 {
            schema: BROWSER_STATUS_SCHEMA.to_string(),
            generated_at: now_rfc3339(),
            platform: "macos".to_string(),
            supported: safari_installed || chrome_installed,
            safari_installed,
            chrome_installed,
            safari_running,
            chrome_running,
            preferred_automation_browser,
            notes,
        })
    }
    #[cfg(not(target_os = "macos"))]
    {
        Ok(AgentBrowserStatusReportV1 {
            schema: BROWSER_STATUS_SCHEMA.to_string(),
            generated_at: now_rfc3339(),
            platform: std::env::consts::OS.to_string(),
            supported: false,
            safari_installed: false,
            chrome_installed: false,
            safari_running: false,
            chrome_running: false,
            preferred_automation_browser: None,
            notes: vec![
                "GUI browser automation is currently implemented only for macOS hosts.".to_string(),
            ],
        })
    }
}

pub fn browser_open(
    request: AgentBrowserOpenRequestV1,
) -> Result<AgentBrowserOpenReportV1, String> {
    #[cfg(target_os = "macos")]
    {
        let browser = request.browser.unwrap_or(AgentBrowserKindV1::Default);
        let activate = request.activate.unwrap_or(true);
        let new_window = request.new_window.unwrap_or(false);
        let requested_url = request.url;

        let (resolved_browser, current_url, title) = match browser {
            AgentBrowserKindV1::Default => {
                open_default_browser(&requested_url)?;
                ("default".to_string(), None, None)
            }
            AgentBrowserKindV1::Safari => {
                ensure_browser_installed(AgentBrowserKindV1::Safari)?;
                let (current_url, title) = run_open_script(
                    AgentBrowserKindV1::Safari,
                    &requested_url,
                    activate,
                    new_window,
                )?;
                ("safari".to_string(), Some(current_url), Some(title))
            }
            AgentBrowserKindV1::Chrome => {
                ensure_browser_installed(AgentBrowserKindV1::Chrome)?;
                let (current_url, title) = run_open_script(
                    AgentBrowserKindV1::Chrome,
                    &requested_url,
                    activate,
                    new_window,
                )?;
                ("chrome".to_string(), Some(current_url), Some(title))
            }
        };

        Ok(AgentBrowserOpenReportV1 {
            schema: BROWSER_OPEN_SCHEMA.to_string(),
            generated_at: now_rfc3339(),
            browser: resolved_browser,
            requested_url,
            ok: true,
            activated: activate,
            new_window,
            current_url,
            title,
        })
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = request;
        Err("GUI browser automation is currently implemented only for macOS hosts".to_string())
    }
}

pub fn browser_eval(
    request: AgentBrowserEvalRequestV1,
) -> Result<AgentBrowserEvalReportV1, String> {
    #[cfg(target_os = "macos")]
    {
        let browser = resolve_eval_browser(request.browser)?;
        ensure_browser_installed(browser)?;
        let activate = request.activate.unwrap_or(true);
        let wait_millis = request.wait_millis.unwrap_or(DEFAULT_WAIT_MILLIS);
        let url = request.url.unwrap_or_default();
        let raw_result = run_eval_script(
            browser,
            &url,
            activate,
            wait_millis,
            &wrap_eval_script(&request.script),
        )?;
        let value = serde_json::from_str::<Value>(&raw_result).ok();
        let current_url = value
            .as_ref()
            .and_then(|payload| payload.get("url"))
            .and_then(Value::as_str)
            .map(str::to_string);
        let title = value
            .as_ref()
            .and_then(|payload| payload.get("title"))
            .and_then(Value::as_str)
            .map(str::to_string);
        Ok(AgentBrowserEvalReportV1 {
            schema: BROWSER_EVAL_SCHEMA.to_string(),
            generated_at: now_rfc3339(),
            browser: browser.as_str().to_string(),
            current_url,
            title,
            value,
            raw_result: Some(raw_result),
        })
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = request;
        Err("GUI browser automation is currently implemented only for macOS hosts".to_string())
    }
}

#[cfg(target_os = "macos")]
fn resolve_eval_browser(
    requested: Option<AgentBrowserKindV1>,
) -> Result<AgentBrowserKindV1, String> {
    match requested.unwrap_or(AgentBrowserKindV1::Chrome) {
        AgentBrowserKindV1::Default => {
            if application_installed("Google Chrome") {
                Ok(AgentBrowserKindV1::Chrome)
            } else if application_installed("Safari") {
                Ok(AgentBrowserKindV1::Safari)
            } else {
                Err(
                    "no supported automation browser found; install Safari or Google Chrome"
                        .to_string(),
                )
            }
        }
        AgentBrowserKindV1::Safari => Ok(AgentBrowserKindV1::Safari),
        AgentBrowserKindV1::Chrome => Ok(AgentBrowserKindV1::Chrome),
    }
}

#[cfg(target_os = "macos")]
fn ensure_browser_installed(browser: AgentBrowserKindV1) -> Result<(), String> {
    let installed = match browser {
        AgentBrowserKindV1::Default => true,
        AgentBrowserKindV1::Safari => application_installed("Safari"),
        AgentBrowserKindV1::Chrome => application_installed("Google Chrome"),
    };
    if installed {
        Ok(())
    } else {
        Err(format!(
            "{} is not installed on this host",
            browser.display_name()
        ))
    }
}

#[cfg(target_os = "macos")]
fn application_installed(name: &str) -> bool {
    match name {
        "Safari" => [
            "/Applications/Safari.app",
            "/System/Applications/Safari.app",
        ]
        .iter()
        .any(|path| std::path::Path::new(path).exists()),
        "Google Chrome" => [
            "/Applications/Google Chrome.app",
            "/System/Applications/Google Chrome.app",
        ]
        .iter()
        .any(|path| std::path::Path::new(path).exists()),
        _ => false,
    }
}

#[cfg(target_os = "macos")]
fn process_running(process_name: &str) -> bool {
    Command::new("pgrep")
        .arg("-x")
        .arg(process_name)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

#[cfg(target_os = "macos")]
fn open_default_browser(url: &str) -> Result<(), String> {
    Command::new("open")
        .arg(url)
        .status()
        .map_err(|error| format!("failed to open default browser: {error}"))
        .and_then(|status| {
            if status.success() {
                Ok(())
            } else {
                Err(format!("default browser open exited with status {status}"))
            }
        })
}

#[cfg(target_os = "macos")]
fn run_open_script(
    browser: AgentBrowserKindV1,
    url: &str,
    activate: bool,
    new_window: bool,
) -> Result<(String, String), String> {
    split_browser_output(&run_osascript(
        &open_script(browser),
        &[url, bool_arg(activate), bool_arg(new_window)],
    )?)
}

#[cfg(target_os = "macos")]
fn run_eval_script(
    browser: AgentBrowserKindV1,
    url: &str,
    activate: bool,
    wait_millis: u64,
    wrapped_script: &str,
) -> Result<String, String> {
    let wait_millis_string = wait_millis.to_string();
    run_osascript(
        &eval_script(browser),
        &[url, bool_arg(activate), &wait_millis_string, wrapped_script],
    )
}

#[cfg(target_os = "macos")]
fn bool_arg(value: bool) -> &'static str {
    if value { "true" } else { "false" }
}

#[cfg(target_os = "macos")]
fn open_script(browser: AgentBrowserKindV1) -> String {
    match browser {
        AgentBrowserKindV1::Safari => r#"
on run argv
  set targetUrl to item 1 of argv
  set shouldActivate to (item 2 of argv) is "true"
  set openNewWindow to (item 3 of argv) is "true"
  tell application "Safari"
    if not running then launch
    if shouldActivate then activate
    if openNewWindow or (count of documents) is 0 then
      make new document with properties {URL:targetUrl}
    else
      set URL of front document to targetUrl
    end if
    delay 1
    return (URL of front document) & linefeed & (name of front document)
  end tell
end run
"#
        .to_string(),
        AgentBrowserKindV1::Chrome => r#"
on run argv
  set targetUrl to item 1 of argv
  set shouldActivate to (item 2 of argv) is "true"
  set openNewWindow to (item 3 of argv) is "true"
  tell application "Google Chrome"
    if not running then launch
    if shouldActivate then activate
    if (count of windows) is 0 then
      make new window
    end if
    if openNewWindow then
      set targetWindow to make new window
      set URL of active tab of targetWindow to targetUrl
    else
      set targetWindow to front window
      set URL of active tab of targetWindow to targetUrl
    end if
    delay 1
    set targetTab to active tab of targetWindow
    return (URL of targetTab) & linefeed & (title of targetTab)
  end tell
end run
"#
        .to_string(),
        AgentBrowserKindV1::Default => unreachable!("default browser uses the 'open' command"),
    }
}

#[cfg(target_os = "macos")]
fn eval_script(browser: AgentBrowserKindV1) -> String {
    match browser {
        AgentBrowserKindV1::Safari => r#"
on run argv
  set targetUrl to item 1 of argv
  set shouldActivate to (item 2 of argv) is "true"
  set waitMillis to (item 3 of argv) as integer
  set userScript to item 4 of argv
  tell application "Safari"
    if not running then launch
    if shouldActivate then activate
    if (count of documents) is 0 then
      make new document
    end if
    if targetUrl is not "" then
      set URL of front document to targetUrl
    end if
  end tell
  delay (waitMillis / 1000)
  tell application "Safari"
    return do JavaScript userScript in front document
  end tell
end run
"#
        .to_string(),
        AgentBrowserKindV1::Chrome => r#"
on run argv
  set targetUrl to item 1 of argv
  set shouldActivate to (item 2 of argv) is "true"
  set waitMillis to (item 3 of argv) as integer
  set userScript to item 4 of argv
  tell application "Google Chrome"
    if not running then launch
    if shouldActivate then activate
    if (count of windows) is 0 then
      make new window
    end if
    if targetUrl is not "" then
      set URL of active tab of front window to targetUrl
    end if
  end tell
  delay (waitMillis / 1000)
  tell application "Google Chrome"
    return execute active tab of front window javascript userScript
  end tell
end run
"#
        .to_string(),
        AgentBrowserKindV1::Default => unreachable!("default browser is not scriptable"),
    }
}

#[cfg(target_os = "macos")]
fn run_osascript(script: &str, args: &[&str]) -> Result<String, String> {
    let mut child = Command::new("osascript")
        .arg("-l")
        .arg("AppleScript")
        .arg("-")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("failed to start osascript: {error}"))?;
    {
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| "failed to capture osascript stdin".to_string())?;
        stdin
            .write_all(script.as_bytes())
            .map_err(|error| format!("failed to write osascript stdin: {error}"))?;
    }
    let output = child
        .wait_with_output()
        .map_err(|error| format!("failed waiting for osascript: {error}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(if stderr.is_empty() {
            format!("osascript exited with status {}", output.status)
        } else {
            format!("osascript failed: {stderr}")
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

#[cfg(target_os = "macos")]
fn split_browser_output(output: &str) -> Result<(String, String), String> {
    let mut parts = output.lines();
    let current_url = parts
        .next()
        .ok_or_else(|| "browser automation returned no URL".to_string())?
        .trim()
        .to_string();
    let title = parts
        .next()
        .ok_or_else(|| "browser automation returned no title".to_string())?
        .trim()
        .to_string();
    Ok((current_url, title))
}

#[cfg(target_os = "macos")]
fn wrap_eval_script(user_script: &str) -> String {
    format!(
        r#"(function() {{
  try {{
    const __ziros_result = (() => {{
{user_script}
    }})();
    return JSON.stringify({{
      ok: true,
      url: window.location.href,
      title: document.title,
      result: __ziros_result
    }});
  }} catch (error) {{
    return JSON.stringify({{
      ok: false,
      url: window.location.href,
      title: document.title,
      error: String(error && error.message ? error.message : error)
    }});
  }}
}})()"#
    )
}

#[cfg(test)]
mod tests {
    use super::wrap_eval_script;
    use crate::types::AgentBrowserKindV1;

    #[test]
    fn browser_kind_labels_are_stable() {
        assert_eq!(AgentBrowserKindV1::Default.as_str(), "default");
        assert_eq!(AgentBrowserKindV1::Safari.display_name(), "Safari");
        assert_eq!(AgentBrowserKindV1::Chrome.display_name(), "Google Chrome");
    }

    #[test]
    fn wrapped_eval_script_captures_page_metadata() {
        let wrapped = wrap_eval_script("return { ok: true, title: document.title };");
        assert!(wrapped.contains("window.location.href"));
        assert!(wrapped.contains("document.title"));
        assert!(wrapped.contains("JSON.stringify"));
    }
}
