use crate::StorageError;
use crate::platform::PlatformDriveInfo;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

pub(crate) fn platform_drive_info() -> Result<PlatformDriveInfo, StorageError> {
    let df_output = run_command("df", &["-k", "/"])?;
    let (device_name, used_bytes, available_bytes) = parse_df_k_output(&df_output)?;
    let base_device = block_device_name(&device_name);
    let sysfs_root = PathBuf::from("/sys/class/block").join(&base_device).join("device");

    Ok(PlatformDriveInfo {
        device_name,
        model: read_trimmed(sysfs_root.join("model")),
        serial: read_trimmed(sysfs_root.join("serial")),
        firmware: read_trimmed(sysfs_root.join("firmware_rev"))
            .or_else(|| read_trimmed(sysfs_root.join("rev"))),
        capacity_bytes: used_bytes.saturating_add(available_bytes),
        used_bytes,
        available_bytes,
        wear_level_percent: None,
        temperature_celsius: read_linux_temperature(&base_device),
        power_on_hours: None,
        smart_available: sysfs_root.exists(),
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

pub(crate) fn block_device_name(device: &str) -> String {
    let name = device.strip_prefix("/dev/").unwrap_or(device);
    if name.starts_with("nvme") {
        if let Some((base, _)) = name.rsplit_once('p')
            && base.chars().last().is_some_and(|value| value.is_ascii_digit())
        {
            return base.to_string();
        }
        return name.to_string();
    }
    name.trim_end_matches(|value: char| value.is_ascii_digit())
        .trim_end_matches('p')
        .to_string()
}

fn read_trimmed(path: PathBuf) -> Option<String> {
    fs::read_to_string(path).ok().map(|value| value.trim().to_string())
}

fn read_linux_temperature(device: &str) -> Option<f64> {
    let hwmon_root = Path::new("/sys/class/block")
        .join(device)
        .join("device")
        .join("hwmon");
    let entries = fs::read_dir(hwmon_root).ok()?;
    for entry in entries.flatten() {
        let temp = entry.path().join("temp1_input");
        if let Some(raw) = read_trimmed(temp)
            && let Ok(value) = raw.parse::<f64>()
        {
            return Some(value / 1000.0);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::{block_device_name, parse_df_k_output};

    #[test]
    fn parses_df_k_output() {
        let output = "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/nvme0n1p2 1000 250 750 25% /\n";
        let (device, used, available) = parse_df_k_output(output).expect("parse");
        assert_eq!(device, "/dev/nvme0n1p2");
        assert_eq!(used, 256_000);
        assert_eq!(available, 768_000);
    }

    #[test]
    fn trims_partition_suffix_from_device_name() {
        assert_eq!(block_device_name("/dev/nvme0n1p2"), "nvme0n1");
        assert_eq!(block_device_name("/dev/sda2"), "sda");
    }
}
