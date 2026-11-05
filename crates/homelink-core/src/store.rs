//! On-disk state, in the per-user config directory:
//! macOS `~/Library/Application Support/homelink`, Windows `%APPDATA%\homelink`.
//! Override with the `HOMELINK_DIR` environment variable.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use homelink_proto::{id_hex, parse_id, DeviceId, Invite, Secret, DEFAULT_PORT};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::identity::Identity;

/// A device allowed to use this host.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Device {
    pub id: String,
    pub name: String,
    pub added: u64,
}

impl Device {
    pub fn device_id(&self) -> Option<DeviceId> {
        parse_id(&self.id)
    }
}

/// An invite created on this host that hasn't been used yet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingInvite {
    pub secret: String,
    pub expires: u64,
}

/// A host this device has paired with.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SavedHost {
    pub name: String,
    pub addr: String,
    pub port: u16,
    pub id: String,
}

impl SavedHost {
    pub fn device_id(&self) -> Result<DeviceId> {
        parse_id(&self.id).ok_or_else(|| anyhow!("saved host has an invalid id"))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct HostSettings {
    pub port: u16,
    /// Let paired devices reach this host's local network.
    pub allow_lan: bool,
    /// DDNS hostname or fixed address to put in invites. Detected if empty.
    pub public_addr: Option<String>,
    /// Try UPnP to forward the port automatically.
    pub upnp: bool,
    /// Ask before pairing a new device.
    pub require_approval: bool,
    /// Desktop app: start sharing as soon as the app opens.
    pub share_on_launch: bool,
}

impl Default for HostSettings {
    fn default() -> Self {
        HostSettings {
            port: DEFAULT_PORT,
            allow_lan: false,
            public_addr: None,
            upnp: true,
            require_approval: true,
            share_on_launch: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Store {
    dir: PathBuf,
}

impl Store {
    pub fn open_default() -> Result<Self> {
        let dir = match std::env::var_os("HOMELINK_DIR") {
            Some(d) => PathBuf::from(d),
            None => dirs::config_dir()
                .ok_or_else(|| anyhow!("no per-user config directory on this system"))?
                .join("homelink"),
        };
        Self::open(dir)
    }

    pub fn open(dir: impl Into<PathBuf>) -> Result<Self> {
        let dir = dir.into();
        fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        restrict_dir(&dir);
        Ok(Store { dir })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn identity(&self) -> Result<Identity> {
        let cert_path = self.dir.join("device.cert");
        let key_path = self.dir.join("device.key");
        if cert_path.exists() && key_path.exists() {
            let cert = fs::read(&cert_path)?;
            let key = fs::read(&key_path)?;
            return Ok(Identity::from_parts(cert, key));
        }
        let id = Identity::generate()?;
        write_atomic(&key_path, id.key_der(), true)?;
        write_atomic(&cert_path, &id.cert, false)?;
        Ok(id)
    }

    pub fn settings(&self) -> Result<HostSettings> {
        self.load("host.json")
    }
    pub fn save_settings(&self, s: &HostSettings) -> Result<()> {
        self.save("host.json", s, false)
    }

    pub fn devices(&self) -> Result<Vec<Device>> {
        self.load("devices.json")
    }
    pub fn save_devices(&self, d: &[Device]) -> Result<()> {
        self.save("devices.json", &d, false)
    }

    pub fn add_device(&self, id: &DeviceId, name: &str) -> Result<()> {
        let mut devices = self.devices()?;
        let hex = id_hex(id);
        devices.retain(|d| d.id != hex);
        devices.push(Device { id: hex, name: name.to_string(), added: crate::now_unix() });
        self.save_devices(&devices)
    }

    /// Remove devices whose id starts with `prefix` (hex). Returns how many.
    pub fn revoke(&self, prefix: &str) -> Result<Vec<Device>> {
        let prefix = prefix.trim().to_lowercase().replace('-', "");
        if prefix.len() < 4 {
            return Err(anyhow!("give at least 4 characters of the device id"));
        }
        let devices = self.devices()?;
        let (gone, keep): (Vec<_>, Vec<_>) =
            devices.into_iter().partition(|d| d.id.starts_with(&prefix));
        if gone.len() > 1 {
            return Err(anyhow!("{} devices match, give more of the id", gone.len()));
        }
        self.save_devices(&keep)?;
        Ok(gone)
    }

    pub fn invites(&self) -> Result<Vec<PendingInvite>> {
        let all: Vec<PendingInvite> = self.load("invites.json")?;
        let now = crate::now_unix();
        Ok(all.into_iter().filter(|i| i.expires > now).collect())
    }

    pub fn create_invite(
        &self,
        host_id: DeviceId,
        addr: String,
        port: u16,
        ttl_secs: u64,
    ) -> Result<Invite> {
        let secret: Secret = crate::random_bytes();
        let expires = crate::now_unix() + ttl_secs;
        let mut invites = self.invites()?;
        invites.push(PendingInvite { secret: hex::encode(secret), expires });
        self.save("invites.json", &invites, true)?;
        Ok(Invite { host_id, secret, expires, addr, port })
    }

    /// Consume an invite secret. Returns `Ok(true)` if it was valid and unexpired,
    /// `Ok(false)` if it existed but expired, `Err` if unknown.
    pub(crate) fn take_invite(&self, secret: &Secret) -> Result<bool, InviteLookup> {
        let all: Vec<PendingInvite> = self.load("invites.json").map_err(|_| InviteLookup::Unknown)?;
        let now = crate::now_unix();
        let mut found = None;
        let mut rest = Vec::new();
        for inv in all {
            let matches = hex::decode(&inv.secret)
                .map(|s| crate::ct_eq(&s, secret))
                .unwrap_or(false);
            if matches {
                found = Some(inv.expires > now);
            } else if inv.expires > now {
                rest.push(inv);
            }
        }
        let _ = self.save("invites.json", &rest, true);
        match found {
            Some(true) => Ok(true),
            Some(false) => Err(InviteLookup::Expired),
            None => Err(InviteLookup::Unknown),
        }
    }

    pub fn hosts(&self) -> Result<Vec<SavedHost>> {
        self.load("hosts.json")
    }

    /// Add or update a host (matched by id).
    pub fn save_host(&self, h: SavedHost) -> Result<()> {
        let mut hosts = self.hosts()?;
        hosts.retain(|x| x.id != h.id);
        hosts.push(h);
        self.save("hosts.json", &hosts, false)
    }

    pub fn remove_host(&self, name: &str) -> Result<bool> {
        let mut hosts = self.hosts()?;
        let before = hosts.len();
        hosts.retain(|h| h.name != name);
        self.save("hosts.json", &hosts, false)?;
        Ok(hosts.len() != before)
    }

    /// Find a saved host by name, or the only one if `name` is None.
    pub fn find_host(&self, name: Option<&str>) -> Result<SavedHost> {
        let hosts = self.hosts()?;
        match name {
            Some(n) => hosts
                .into_iter()
                .find(|h| h.name == n)
                .ok_or_else(|| anyhow!("no saved host called '{n}'")),
            None => match hosts.len() {
                0 => Err(anyhow!("no saved hosts yet, add one with an invite code")),
                1 => Ok(hosts.into_iter().next().unwrap()),
                _ => Err(anyhow!("several saved hosts, say which one")),
            },
        }
    }

    fn load<T: DeserializeOwned + Default>(&self, name: &str) -> Result<T> {
        let path = self.dir.join(name);
        match fs::read(&path) {
            Ok(b) => serde_json::from_slice(&b).with_context(|| format!("reading {}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(T::default()),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    fn save<T: Serialize + ?Sized>(&self, name: &str, value: &T, private: bool) -> Result<()> {
        let json = serde_json::to_vec_pretty(value)?;
        write_atomic(&self.dir.join(name), &json, private)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum InviteLookup {
    Unknown,
    Expired,
}

fn write_atomic(path: &Path, data: &[u8], private: bool) -> Result<()> {
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, data).with_context(|| format!("writing {}", tmp.display()))?;
    if private {
        restrict_file(&tmp);
    }
    fs::rename(&tmp, path).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

#[cfg(unix)]
fn restrict_file(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
}

#[cfg(unix)]
fn restrict_dir(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o700));
}

// %APPDATA% is already private to the user on Windows.
#[cfg(not(unix))]
fn restrict_file(_: &Path) {}
#[cfg(not(unix))]
fn restrict_dir(_: &Path) {}
