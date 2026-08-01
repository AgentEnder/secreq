//! `secreq link …` — pair, inspect, and revoke LAN approval devices.

use anyhow::Result;

use crate::daemon::client as daemon_client;

/// Open a one-minute enrollment window and render its URL as a terminal QR.
pub fn pair() -> Result<i32> {
    let url = daemon_client::open_link_pairing()?;
    println!("Scan this code from the device you want to pair:\n");
    print!("{}", crate::link::qr::render(&url)?);
    println!("\nOr open this address on that device:\n{url}\n");
    println!("This one-time link expires in 60 seconds.");
    Ok(0)
}

/// List paired nicknames. Public keys stay in the owner-only registry and do
/// not make this human-facing output more useful, so they are omitted.
pub fn list() -> Result<i32> {
    let devices = daemon_client::list_link_devices()?;
    print!("{}", render_device_list(&devices));
    Ok(0)
}

/// Revoke a nickname immediately. The daemon reloads the registry on every
/// signed decision, so an already-in-flight request from this device is also
/// refused after this returns.
pub fn remove(nickname: &str) -> Result<i32> {
    daemon_client::remove_link_device(nickname)?;
    println!("Unlinked `{nickname}`.");
    Ok(0)
}

fn render_device_list(devices: &[crate::link::devices::Device]) -> String {
    if devices.is_empty() {
        return "No linked devices.\n".to_owned();
    }
    let mut out = format!(
        "{} linked device{}:\n",
        devices.len(),
        if devices.len() == 1 { "" } else { "s" }
    );
    for device in devices {
        out.push_str("  ");
        out.push_str(&device.nickname);
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device(nickname: &str) -> crate::link::devices::Device {
        crate::link::devices::Device {
            nickname: nickname.to_owned(),
            public_key_b64: "unused".to_owned(),
            enrolled_at: 1,
            last_seen: None,
        }
    }

    #[test]
    fn list_output_names_devices_without_dumping_keys() {
        let rendered = render_device_list(&[device("phone"), device("tablet")]);
        assert_eq!(rendered, "2 linked devices:\n  phone\n  tablet\n");
        assert!(!rendered.contains("unused"));
    }

    #[test]
    fn empty_list_has_a_direct_next_step() {
        assert_eq!(render_device_list(&[]), "No linked devices.\n");
    }
}
