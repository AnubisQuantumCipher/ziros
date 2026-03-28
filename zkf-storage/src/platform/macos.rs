use crate::StorageError;
use crate::platform::PlatformDriveInfo;
use std::process::Command;

pub(crate) fn platform_drive_info() -> Result<PlatformDriveInfo, StorageError> {
    let diskutil_output = run_command("diskutil", &["info", "/"])?;
    let df_output = run_command("df", &["-k", "/"])?;
    let profiler_output = run_command("system_profiler", &["SPNVMeDataType", "-detailLevel", "mini"])
        .unwrap_or_default();

    let (device_name, df_used_bytes, df_available_bytes) = parse_df_k_output(&df_output)?;
    let capacity_from_diskutil = parse_bytes_from_key(&diskutil_output, "Disk Size")
        .or_else(|| parse_bytes_from_key(&diskutil_output, "Container Total Space"))
        .unwrap_or_else(|| df_used_bytes.saturating_add(df_available_bytes));
    let available_bytes = parse_bytes_from_key(&diskutil_output, "Container Free Space")
        .or_else(|| parse_bytes_from_key(&diskutil_output, "Available Space"))
        .unwrap_or(df_available_bytes);
    let used_bytes = capacity_from_diskutil
        .checked_sub(available_bytes)
        .unwrap_or(df_used_bytes);
    let model = parse_value(&profiler_output, "Model")
        .or_else(|| parse_value(&diskutil_output, "Device / Media Name"))
        .or_else(|| parse_value(&diskutil_output, "Media Name"));
    let serial = parse_value(&profiler_output, "Serial Number");
    let firmware = parse_value(&profiler_output, "Revision");
    let smart_status = parse_value(&profiler_output, "S.M.A.R.T. status")
        .or_else(|| parse_value(&diskutil_output, "SMART Status"));

    Ok(PlatformDriveInfo {
        device_name,
        model,
        serial,
        firmware,
        capacity_bytes: capacity_from_diskutil,
        used_bytes,
        available_bytes,
        wear_level_percent: None,
        temperature_celsius: None,
        power_on_hours: None,
        smart_available: smart_status.is_some(),
    })
}

fn run_command(program: &str, args: &[&str]) -> Result<String, StorageError> {
    let output = Command::new(program).args(args).output()?;
    if !output.status.success() {
        return Err(StorageError::CommandFailed {
            command: format!("{program} {}", args.join(" ")),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn parse_value(output: &str, key: &str) -> Option<String> {
    output.lines().find_map(|line| {
        let trimmed = line.trim();
        let (left, right) = trimmed.split_once(':')?;
        if left.trim() == key {
            Some(right.trim().to_string())
        } else {
            None
        }
    })
}

fn parse_bytes_from_key(output: &str, key: &str) -> Option<u64> {
    parse_value(output, key).and_then(|value| extract_parenthesized_bytes(&value))
}

fn extract_parenthesized_bytes(value: &str) -> Option<u64> {
    let bytes_text = value
        .split_once('(')?
        .1
        .split_once(' ')?
        .0
        .replace(',', "");
    bytes_text.parse::<u64>().ok()
}

pub(crate) fn parse_df_k_output(output: &str) -> Result<(String, u64, u64), StorageError> {
    let line = output
        .lines()
        .filter(|line| !line.trim().is_empty())
        .nth(1)
        .ok_or_else(|| StorageError::Parse("missing df payload".to_string()))?;
    let columns = line.split_whitespace().collect::<Vec<_>>();
    if columns.len() < 5 {
        return Err(StorageError::Parse(format!(
            "unexpected df payload: {line}"
        )));
    }
    let device = columns[0].to_string();
    let used_kb = columns[2]
        .parse::<u64>()
        .map_err(|error| StorageError::Parse(format!("parse df used blocks: {error}")))?;
    let available_kb = columns[3]
        .parse::<u64>()
        .map_err(|error| StorageError::Parse(format!("parse df available blocks: {error}")))?;
    Ok((
        device,
        used_kb.saturating_mul(1024),
        available_kb.saturating_mul(1024),
    ))
}

#[cfg(test)]
mod tests {
    use super::{parse_bytes_from_key, parse_df_k_output};

    #[test]
    fn parses_df_k_output() {
        let output = "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/disk3s1s1 976490576 1000 2000 1% /\n";
        let (device, used, available) = parse_df_k_output(output).expect("parse");
        assert_eq!(device, "/dev/disk3s1s1");
        assert_eq!(used, 1_024_000);
        assert_eq!(available, 2_048_000);
    }

    #[test]
    fn parses_container_free_space_from_diskutil() {
        let output = "\
Disk Size:                 994.7 GB (994662584320 Bytes)\n\
Container Total Space:     994.7 GB (994662584320 Bytes)\n\
Container Free Space:      164.1 GB (164143951872 Bytes)\n";
        assert_eq!(
            parse_bytes_from_key(output, "Container Free Space"),
            Some(164_143_951_872)
        );
        assert_eq!(
            parse_bytes_from_key(output, "Container Total Space"),
            Some(994_662_584_320)
        );
    }
}
