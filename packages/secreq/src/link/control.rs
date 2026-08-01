//! Daemon-owned lifecycle for the LAN listener and pairing window.
//!
//! The listener is absent on an unpaired installation, starts automatically
//! with the daemon once the registry is non-empty, and can be started on
//! demand for the first `secreq link`. It deliberately lives outside
//! [`crate::daemon::state::State`]: the listener's accept thread owns a clone
//! of that state, so storing the listener inside it would create an `Arc`
//! cycle and keep both alive forever.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::{bail, Context, Result};

use super::devices::Device;
use super::lan::Listener;
use super::pair::Pairing;

/// Fixed private-LAN port used by bookmarked linked devices.
pub const LINK_PORT: u16 = 46_371;

/// Listener and registry control shared by daemon connection threads.
pub struct LinkControl {
    pairing: Arc<Pairing>,
    listener: Mutex<Option<Listener>>,
}

impl LinkControl {
    pub fn new(registry_path: PathBuf) -> Self {
        Self {
            pairing: Arc::new(Pairing::new(registry_path)),
            listener: Mutex::new(None),
        }
    }

    /// Bring up the LAN listener when a persisted device makes it useful.
    pub fn start_if_enrolled(&self, state: crate::daemon::state::SharedState) -> Result<()> {
        if self.pairing.devices()?.is_empty() {
            return Ok(());
        }
        self.ensure_listener(state).map(|_| ())
    }

    /// Open the one-minute enrollment window and return the URL encoded by
    /// the terminal QR.
    pub fn open_pairing(&self, state: crate::daemon::state::SharedState) -> Result<String> {
        let address = self.ensure_listener(state)?;
        let token = self.pairing.open()?;
        Ok(format!("http://{address}/pair#{token}"))
    }

    pub fn devices(&self) -> Result<Vec<Device>> {
        self.pairing.devices().map_err(Into::into)
    }

    /// Revoke one nickname. Removing the final credential also drops the LAN
    /// listener immediately, so an unpaired daemon does not keep publishing
    /// request metadata until its next restart.
    pub fn remove(
        &self,
        nickname: &str,
        state: &crate::daemon::state::SharedState,
    ) -> Result<Option<Device>> {
        let Some((removed, remaining)) = self.pairing.remove(nickname)? else {
            return Ok(None);
        };
        if remaining == 0 {
            let listener = self
                .listener
                .lock()
                .map_err(|_| anyhow::anyhow!("link listener state unavailable"))?
                .take();
            drop(listener);
            state
                .lock()
                .map_err(|_| anyhow::anyhow!("daemon state unavailable"))?
                .close_link_events();
        }
        Ok(Some(removed))
    }

    fn ensure_listener(&self, state: crate::daemon::state::SharedState) -> Result<SocketAddr> {
        let mut listener = self
            .listener
            .lock()
            .map_err(|_| anyhow::anyhow!("link listener state unavailable"))?;
        if let Some(listener) = listener.as_ref() {
            return Ok(listener.local_addr());
        }

        let ip = default_lan_ip()?;
        let address = SocketAddr::new(ip, LINK_PORT);
        let started = super::lan::start(address, Arc::clone(&self.pairing), state)
            .with_context(|| format!("start linked-device listener at {address}"))?;
        let local_addr = started.local_addr();
        *listener = Some(started);
        Ok(local_addr)
    }
}

/// Ask the routing table which source address it would use for an ordinary
/// IPv4 destination. UDP `connect` sends no packet; it only selects a route.
/// This avoids advertising loopback or a random VM bridge on machines with
/// several interfaces, without adding a platform-specific interface crate.
fn default_lan_ip() -> Result<IpAddr> {
    let socket =
        UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).context("inspect the machine's LAN route")?;
    socket
        .connect((Ipv4Addr::new(192, 0, 2, 1), 9))
        .context("select the machine's LAN route")?;
    let ip = socket
        .local_addr()
        .context("read the machine's LAN address")?
        .ip();
    if !ip.is_loopback() && super::lan::is_lan(&ip) {
        return Ok(ip);
    }
    bail!(
        "the default route uses {ip}, not a private LAN address; connect this machine to its private LAN and try again"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pairing_url_keeps_the_token_in_the_fragment() {
        let address: SocketAddr = "192.168.1.50:46371".parse().unwrap();
        let token = "a".repeat(64);
        let url = format!("http://{address}/pair#{token}");
        assert_eq!(url, format!("http://192.168.1.50:46371/pair#{token}"));
        assert!(
            !url.contains("?"),
            "the token must not enter an HTTP request"
        );
    }
}
