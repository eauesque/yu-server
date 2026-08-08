//! LAN Cowork machine-info collection and GPU probes (F1).

use std::{
    collections::HashMap,
    io::Read,
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

use chrono::{Local, SecondsFormat};
use serde_json::{json, Value};

fn round1(value: f64) -> f64 {
    (value * 10.0).round() / 10.0
}

fn command_output(command: &str, args: &[&str], timeout: Duration) -> Option<String> {
    let mut child = Command::new(command)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let mut stdout = child.stdout.take()?;
    let reader = std::thread::spawn(move || {
        let mut output = String::new();
        stdout.read_to_string(&mut output).ok()?;
        Some(output)
    });
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait().ok()? {
            Some(status) if status.success() => {
                return reader.join().ok().flatten();
            }
            Some(_) => {
                let _ = reader.join();
                return None;
            }
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = reader.join();
                return None;
            }
            None => std::thread::sleep(Duration::from_millis(10)),
        }
    }
}

fn git_info(repo_path: &Path) -> Value {
    let run = |args: &[&str]| {
        command_output("git", args, Duration::from_secs(5)).map(|value| value.trim().to_owned())
    };
    let path = repo_path.to_string_lossy();
    match (
        run(&["-C", &path, "rev-parse", "--abbrev-ref", "HEAD"]),
        run(&["-C", &path, "rev-parse", "--short", "HEAD"]),
        run(&["-C", &path, "status", "--porcelain", "--untracked-files=no"]),
    ) {
        (Some(branch), Some(commit), Some(dirty)) => {
            json!({"branch": branch, "commit": commit, "dirty": !dirty.is_empty()})
        }
        _ => json!({"branch": null, "commit": null, "dirty": null}),
    }
}

fn cpu_name() -> String {
    std::env::consts::ARCH.to_owned()
}

fn cpu_physical_cores() -> u64 {
    let Ok(text) = std::fs::read_to_string("/proc/cpuinfo") else {
        return 0;
    };
    let mut cores = std::collections::HashSet::new();
    for block in text.split("\n\n") {
        let physical = block.lines().find_map(|line| {
            line.split_once(':')
                .filter(|(key, _)| key.trim() == "physical id")
                .map(|(_, value)| value.trim())
        });
        let core = block.lines().find_map(|line| {
            line.split_once(':')
                .filter(|(key, _)| key.trim() == "core id")
                .map(|(_, value)| value.trim())
        });
        if let (Some(physical), Some(core)) = (physical, core) {
            cores.insert((physical.to_owned(), core.to_owned()));
        }
    }
    cores.len() as u64
}

fn cpu_stat() -> Option<(u64, u64)> {
    let line = std::fs::read_to_string("/proc/stat")
        .ok()?
        .lines()
        .next()?
        .to_owned();
    let fields: Vec<u64> = line
        .split_whitespace()
        .skip(1)
        .filter_map(|field| field.parse().ok())
        .collect();
    (fields.len() >= 4).then(|| {
        (
            fields.iter().sum(),
            fields[3] + fields.get(4).copied().unwrap_or(0),
        )
    })
}

fn cpu_usage_pct() -> f64 {
    let Some((total_before, idle_before)) = cpu_stat() else {
        return 0.0;
    };
    std::thread::sleep(std::time::Duration::from_millis(100));
    let Some((total_after, idle_after)) = cpu_stat() else {
        return 0.0;
    };
    let total = total_after.saturating_sub(total_before);
    if total == 0 {
        0.0
    } else {
        round1((total - idle_after.saturating_sub(idle_before)) as f64 / total as f64 * 100.0)
    }
}

fn os_info() -> Value {
    #[cfg(unix)]
    {
        let mut name = std::mem::MaybeUninit::<libc::utsname>::uninit();
        if unsafe { libc::uname(name.as_mut_ptr()) } == 0 {
            let name = unsafe { name.assume_init() };
            let read = |value: &[libc::c_char]| {
                unsafe { std::ffi::CStr::from_ptr(value.as_ptr()) }
                    .to_string_lossy()
                    .into_owned()
            };
            return json!({"system": read(&name.sysname), "release": read(&name.release), "version": read(&name.version)});
        }
    }
    let system = match std::env::consts::OS {
        "windows" => "Windows",
        other => other,
    };
    json!({"system": system, "release": "", "version": ""})
}

fn gpu(name: String, total: Option<f64>, used: Option<f64>, utilization: Option<f64>) -> Value {
    json!({"name": name, "vram_total_gb": total, "vram_used_gb": used, "utilization_pct": utilization})
}

fn gpu_nvidia_smi() -> Option<Vec<Value>> {
    let output = command_output(
        "nvidia-smi",
        &[
            "--query-gpu=name,memory.total,memory.used,utilization.gpu",
            "--format=csv,noheader,nounits",
        ],
        Duration::from_secs(3),
    )?;
    let gpus: Vec<_> = output
        .lines()
        .filter_map(|line| {
            let fields: Vec<_> = line.split(',').map(str::trim).collect();
            if fields.len() < 4 {
                return None;
            }
            let total = fields[1].parse::<f64>().ok()?;
            let used = fields[2].parse::<f64>().ok()?;
            Some(gpu(
                fields[0].to_owned(),
                Some(round1(total / 1024.0)),
                Some(round1(used / 1024.0)),
                fields[3].parse().ok(),
            ))
        })
        .collect();
    (!gpus.is_empty()).then_some(gpus)
}

fn rocminfo_names() -> Vec<String> {
    command_output("rocminfo", &[], Duration::from_secs(8))
        .map(|output| {
            output
                .split("*******")
                .filter_map(|block| {
                    (block.contains("Device Type:             GPU")
                        || block.contains("Device Type: GPU"))
                    .then(|| {
                        block.lines().find_map(|line| {
                            line.split_once("Marketing Name:")
                                .map(|(_, value)| value.trim().to_owned())
                        })
                    })
                    .flatten()
                })
                .filter(|name| !name.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

fn gpu_rocm_smi() -> Option<Vec<Value>> {
    let output = command_output(
        "rocm-smi",
        &[
            "--showproductname",
            "--showmeminfo",
            "vram",
            "--showuse",
            "--json",
        ],
        Duration::from_secs(5),
    )?;
    let data = serde_json::from_str::<Value>(&output).ok()?;
    let cards = data
        .as_object()?
        .iter()
        .filter(|(key, value)| key.to_ascii_lowercase().starts_with("card") && value.is_object())
        .collect::<Vec<_>>();
    if cards.is_empty() {
        return None;
    }
    let names = rocminfo_names();
    Some(
        cards
            .into_iter()
            .enumerate()
            .map(|(index, (_, card))| {
                let get = |key| {
                    card.get(key)
                        .and_then(Value::as_str)
                        .and_then(|value| value.trim().parse::<f64>().ok())
                };
                let total = get("VRAM Total Memory (B)");
                let name = names
                    .get(index)
                    .cloned()
                    .or_else(|| {
                        ["Card series", "Card model", "Marketing Name", "Card SKU"]
                            .iter()
                            .find_map(|key| {
                                card.get(*key).and_then(Value::as_str).map(str::to_owned)
                            })
                    })
                    .unwrap_or_default();
                gpu(
                    name,
                    total.map(|value| round1(value / 1e9)),
                    total
                        .and_then(|_| get("VRAM Total Used Memory (B)"))
                        .map(|value| round1(value / 1e9)),
                    card.get("GPU use (%)")
                        .and_then(Value::as_str)
                        .and_then(|value| value.trim().parse().ok()),
                )
            })
            .collect(),
    )
}

fn gpu_macos() -> Option<Vec<Value>> {
    if !cfg!(target_os = "macos") {
        return None;
    }
    let output = command_output(
        "system_profiler",
        &["SPDisplaysDataType"],
        Duration::from_secs(5),
    )?;
    let mut name = None;
    let mut total = None;
    for line in output.lines().map(str::trim) {
        if name.is_none() {
            name = line
                .strip_prefix("Chipset Model:")
                .map(|value| value.trim().to_owned());
        }
        if total.is_none() && line.starts_with("VRAM") {
            let fields: Vec<_> = line
                .split_once(':')
                .map(|(_, value)| value.split_whitespace().collect())
                .unwrap_or_default();
            if fields.len() >= 2 {
                total = fields[0].replace(',', "").parse::<f64>().ok().map(|value| {
                    round1(if fields[1].to_ascii_uppercase().starts_with("MB") {
                        value / 1024.0
                    } else {
                        value
                    })
                });
            }
        }
    }
    name.map(|name| vec![gpu(name, total, None, None)])
}

fn gpu_windows_wmi() -> Vec<Value> {
    if !cfg!(target_os = "windows") {
        return Vec::new();
    }
    command_output(
        "powershell",
        &[
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "(Get-CimInstance Win32_VideoController).Name",
        ],
        Duration::from_secs(5),
    )
    .map(|output| {
        output
            .lines()
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map(|name| gpu(name.to_owned(), None, None, None))
            .collect()
    })
    .unwrap_or_default()
}

fn gpu_info_from(
    probes: [Option<Vec<Value>>; 3],
    windows: impl FnOnce() -> Vec<Value>,
) -> Vec<Value> {
    if let Some(gpus) = probes.into_iter().flatten().next() {
        return gpus;
    }
    let windows = windows();
    if windows.is_empty() {
        vec![gpu(String::new(), None, None, None)]
    } else {
        windows
    }
}

fn gpu_info() -> Vec<Value> {
    gpu_info_from(
        [gpu_nvidia_smi(), gpu_rocm_smi(), gpu_macos()],
        gpu_windows_wmi,
    )
}

fn meminfo() -> HashMap<String, u64> {
    std::fs::read_to_string("/proc/meminfo")
        .ok()
        .map(|text| {
            text.lines()
                .filter_map(|line| {
                    let (key, value) = line.split_once(':')?;
                    Some((
                        key.to_owned(),
                        value.split_whitespace().next()?.parse::<u64>().ok()? * 1024,
                    ))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn ram_from_meminfo(info: &HashMap<String, u64>) -> Value {
    let total = *info.get("MemTotal").unwrap_or(&0) as f64;
    let free = *info.get("MemFree").unwrap_or(&0) as f64;
    let cached = *info.get("Cached").unwrap_or(&0) as f64;
    let buffers = *info.get("Buffers").unwrap_or(&0) as f64;
    let used = (total - free - cached - buffers).max(total - free);
    let pct = if total == 0.0 {
        0.0
    } else {
        (total - *info.get("MemAvailable").unwrap_or(&0) as f64) / total * 100.0
    };
    json!({"total_gb": round1(total / 1e9), "used_gb": round1(used / 1e9), "pct": round1(pct)})
}

fn disk_pct(total: f64, free: f64, available: f64) -> f64 {
    let used = total - free;
    if used + available == 0.0 {
        0.0
    } else {
        used / (used + available) * 100.0
    }
}

#[cfg(unix)]
fn disk_info(path: &Path) -> Value {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let Ok(path_c) = CString::new(path.as_os_str().as_bytes()) else {
        return zero_disk(path);
    };
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    if unsafe { libc::statvfs(path_c.as_ptr(), stat.as_mut_ptr()) } != 0 {
        return zero_disk(path);
    }
    let stat = unsafe { stat.assume_init() };
    let unit = stat.f_frsize as f64;
    let total = stat.f_blocks as f64 * unit;
    let used = total - stat.f_bfree as f64 * unit;
    let available = stat.f_bavail as f64 * unit;
    json!({"path": path.to_string_lossy(), "total_gb": round1(total / 1e9), "used_gb": round1(used / 1e9), "pct": round1(disk_pct(total, stat.f_bfree as f64 * unit, available))})
}

fn zero_disk(path: &Path) -> Value {
    json!({"path": path.to_string_lossy(), "total_gb": 0.0, "used_gb": 0.0, "pct": 0.0})
}

fn collect_for_platform(
    version: &str,
    roles: &[Value],
    repo_path: &Path,
    gpu_name: &str,
    start_time: Instant,
    linux: bool,
) -> Value {
    let mut gpus = gpu_info();
    if !gpu_name.is_empty() {
        gpus[0]["name"] = json!(gpu_name);
    }
    let ram = if linux {
        ram_from_meminfo(&meminfo())
    } else {
        json!({"total_gb": 0.0, "used_gb": 0.0, "pct": 0.0})
    };
    #[cfg(unix)]
    let disk = if linux {
        disk_info(repo_path)
    } else {
        zero_disk(repo_path)
    };
    #[cfg(not(unix))]
    let disk = zero_disk(repo_path);
    json!({"version": version, "os": os_info(), "cpu": {"name": cpu_name(), "cores_physical": if linux { cpu_physical_cores() } else { 0 }, "cores_logical": std::thread::available_parallelism().map(|n| n.get()).unwrap_or(0), "usage_pct": if linux { cpu_usage_pct() } else { 0.0}}, "ram": ram, "gpu": gpus[0], "gpus": gpus, "disk": disk, "process_uptime_sec": start_time.elapsed().as_secs(), "git": git_info(repo_path), "roles": roles, "collected_at": Local::now().to_rfc3339_opts(SecondsFormat::Micros, false)})
}

/// Collect the fixed machine-info schema used by LAN Cowork fleet APIs.
pub fn collect(
    version: &str,
    roles: &[Value],
    repo_path: &Path,
    gpu_name: &str,
    start_time: Instant,
) -> Value {
    collect_for_platform(
        version,
        roles,
        repo_path,
        gpu_name,
        start_time,
        cfg!(target_os = "linux"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fleet_machine_info_schema_and_roles_match_python() {
        let roles = vec![json!("chief")];
        let info = collect("4.559.0", &roles, Path::new("."), "", Instant::now());
        let keys: Vec<_> = info
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            keys,
            [
                "collected_at",
                "cpu",
                "disk",
                "git",
                "gpu",
                "gpus",
                "os",
                "process_uptime_sec",
                "ram",
                "roles",
                "version"
            ]
        );
        assert_eq!(info["roles"], json!(roles));
        assert_eq!(info["cpu"]["name"], std::env::consts::ARCH);
    }

    #[test]
    fn ram_percent_is_memavailable_not_used_ratio() {
        let info = HashMap::from([
            ("MemTotal".into(), 1000),
            ("MemFree".into(), 100),
            ("Cached".into(), 100),
            ("Buffers".into(), 100),
            ("MemAvailable".into(), 400),
        ]);
        assert_eq!(ram_from_meminfo(&info)["pct"], 60.0);
    }

    #[test]
    fn disk_percent_uses_available_blocks_not_total() {
        assert_eq!(round1(disk_pct(1_000.0, 200.0, 500.0)), 61.5);
        assert_ne!(round1(disk_pct(1_000.0, 200.0, 500.0)), 80.0);
    }

    #[test]
    fn non_linux_collect_keeps_zero_resource_schema() {
        let info = collect_for_platform("v", &[], Path::new("."), "", Instant::now(), false);
        assert_eq!(
            info["ram"],
            json!({"total_gb": 0.0, "used_gb": 0.0, "pct": 0.0})
        );
        assert_eq!(
            info["disk"],
            json!({"path": ".", "total_gb": 0.0, "used_gb": 0.0, "pct": 0.0})
        );
    }

    #[test]
    fn gpu_fallback_has_fixed_shape() {
        assert_eq!(
            gpu_info_from([None, None, None], Vec::new),
            vec![gpu(String::new(), None, None, None)]
        );
    }

    #[test]
    fn collect_soft_fails_git_errors() {
        let info = collect(
            "v",
            &[],
            Path::new("/missing-fleet-repo"),
            "",
            Instant::now(),
        );
        assert_eq!(
            info["git"],
            json!({"branch": null, "commit": null, "dirty": null})
        );
        assert!(info["cpu"].is_object());
    }
}
