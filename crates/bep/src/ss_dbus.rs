//! SPIKE (gominimal/minimal#3849): Secret Service over D-Bus through the
//! `secret-service` crate, in place of `secret-tool`. Throwaway code: it
//! shows the calls the real change makes for the three uses (the proxy's
//! keys, the GitHub sign-in, `min secret` store references) and how their
//! errors sort into [`KeyError`]'s locked and unreachable causes.
//!
//! No call here ever unlocks or prompts: a search returns locked and
//! unlocked item paths apart, and only an unlocked item's secret is read.

use std::collections::HashMap;
use std::time::Duration;

use secret_service::blocking::{Collection, Item, SecretService};
use secret_service::{EncryptionType, Error};
use zeroize::Zeroizing;

use crate::keys::{KeyError, Role};

/// The content type `secret-tool store` gives each item.
pub const CONTENT_TYPE: &str = "text/plain";

/// Why a call failed, sorted as `secret_service::sort` sorts
/// `secret-tool`'s messages.
#[derive(Debug)]
pub enum Cause {
    /// The collection or item is locked. Nothing was unlocked.
    Locked(String),
    /// No session bus, or no Secret Service on it.
    Unreachable(String),
    /// Anything else.
    Other(String),
}

impl Cause {
    /// The proxy-key error for this cause, as `secret_service.rs` maps
    /// `secret-tool`'s output.
    #[must_use]
    pub fn into_key_error(self, role: Role) -> KeyError {
        match self {
            Cause::Locked(detail) => KeyError::Locked { role, detail },
            Cause::Unreachable(detail) => KeyError::Unreachable { role, detail },
            Cause::Other(detail) => KeyError::Store { role, detail },
        }
    }
}

/// D-Bus error names that mean no Secret Service answers on this bus.
const UNREACHABLE_NAMES: &[&str] = &[
    "org.freedesktop.DBus.Error.ServiceUnknown",
    "org.freedesktop.DBus.Error.NameHasNoOwner",
    "org.freedesktop.DBus.Error.NoServer",
    "org.freedesktop.DBus.Error.Disconnected",
];

/// D-Bus error names that mean the object is locked.
const LOCKED_NAMES: &[&str] = &["org.freedesktop.Secret.Error.IsLocked"];

fn sort_zbus(err: &zbus::Error) -> Option<Cause> {
    let text = err.to_string();
    match err {
        zbus::Error::MethodError(name, _, _) => {
            let name = name.as_str();
            if UNREACHABLE_NAMES.contains(&name) {
                Some(Cause::Unreachable(text))
            } else if LOCKED_NAMES.contains(&name) {
                Some(Cause::Locked(text))
            } else {
                None
            }
        }
        zbus::Error::FDO(fdo) => sort_fdo(fdo),
        zbus::Error::Address(_) | zbus::Error::InterfaceNotFound => Some(Cause::Unreachable(text)),
        zbus::Error::InputOutput(io)
            if matches!(
                io.kind(),
                std::io::ErrorKind::NotFound
                    | std::io::ErrorKind::ConnectionRefused
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::PermissionDenied
            ) =>
        {
            Some(Cause::Unreachable(text))
        }
        _ => None,
    }
}

fn sort_fdo(err: &zbus::fdo::Error) -> Option<Cause> {
    use zbus::fdo::Error as F;
    let text = err.to_string();
    match err {
        F::ServiceUnknown(_) | F::NameHasNoOwner(_) | F::NoServer(_) | F::Disconnected(_) => {
            Some(Cause::Unreachable(text))
        }
        F::ZBus(inner) => sort_zbus(inner),
        _ => None,
    }
}

/// Sorts a crate error by cause.
#[must_use]
pub fn sort(err: &Error) -> Cause {
    let text = err.to_string();
    let sorted = match err {
        Error::Locked => Some(Cause::Locked(text.clone())),
        Error::Unavailable => Some(Cause::Unreachable(text.clone())),
        Error::Zbus(z) => sort_zbus(z),
        Error::ZbusFdo(f) => sort_fdo(f),
        _ => None,
    };
    sorted.unwrap_or(Cause::Other(text))
}

/// A connection to Secret Service whose every method call gives up after
/// `timeout`, so a stalled provider never holds a caller forever.
///
/// # Errors
///
/// The sorted cause when no Secret Service answers.
pub fn connect(timeout: Duration) -> Result<SecretService<'static>, Cause> {
    let conn = zruntime::block_on(async {
        zbus::connection::Builder::session()?
            .method_timeout(timeout)
            .build()
            .await
    })
    .map_err(|e| {
        sort_zbus(&e).unwrap_or_else(|| Cause::Unreachable(format!("session bus: {e}")))
    })?;
    SecretService::connect_with_existing(EncryptionType::Dh, conn).map_err(|e| sort(&e))
}

/// What a search found under some attributes. No secret is read.
pub enum Found<'a> {
    /// No item matches.
    None,
    /// At least one item matches, and every match is locked.
    Locked,
    /// The first unlocked match.
    Unlocked(Item<'a>),
}

/// Searches every collection for items with `attributes`. `SearchItems`
/// returns object paths only, split into unlocked and locked.
///
/// # Errors
///
/// The sorted cause.
pub fn find<'a>(
    ss: &'a SecretService<'a>,
    attributes: &[(&str, &str)],
) -> Result<Found<'a>, Cause> {
    let attrs: HashMap<&str, &str> = attributes.iter().copied().collect();
    let mut found = ss.search_items(attrs).map_err(|e| sort(&e))?;
    if !found.unlocked.is_empty() {
        return Ok(Found::Unlocked(found.unlocked.swap_remove(0)));
    }
    if found.locked.is_empty() {
        Ok(Found::None)
    } else {
        Ok(Found::Locked)
    }
}

/// The secret under `attributes`, `None` when no item matches, and
/// [`Cause::Locked`] when only a locked item does. Never prompts.
///
/// # Errors
///
/// The sorted cause.
pub fn lookup(
    ss: &SecretService<'_>,
    attributes: &[(&str, &str)],
) -> Result<Option<Zeroizing<Vec<u8>>>, Cause> {
    match find(ss, attributes)? {
        Found::None => Ok(None),
        Found::Locked => Err(Cause::Locked(
            "Secret Service lists the item but it is locked".into(),
        )),
        Found::Unlocked(item) => item
            .get_secret()
            .map(|v| Some(Zeroizing::new(v)))
            .map_err(|e| sort(&e)),
    }
}

/// The default collection, the one `secret-tool store` writes to, and
/// [`Cause::Locked`] when it is locked. Never prompts.
///
/// # Errors
///
/// The sorted cause.
pub fn default_collection<'a>(ss: &'a SecretService<'a>) -> Result<Collection<'a>, Cause> {
    let collection = ss.get_default_collection().map_err(|e| sort(&e))?;
    if collection.is_locked().map_err(|e| sort(&e))? {
        return Err(Cause::Locked("the default collection is locked".into()));
    }
    Ok(collection)
}

/// Stores `secret` under `attributes` in the default collection, in place
/// of the item whose attributes all match (`CreateItem` with replace).
///
/// # Errors
///
/// The sorted cause.
pub fn store(
    ss: &SecretService<'_>,
    label: &str,
    attributes: &[(&str, &str)],
    secret: &[u8],
) -> Result<(), Cause> {
    let collection = default_collection(ss)?;
    let attrs: HashMap<&str, &str> = attributes.iter().copied().collect();
    collection
        .create_item(label, attrs, secret, true, CONTENT_TYPE)
        .map(|_| ())
        .map_err(|e| sort(&e))
}

/// Removes every unlocked item under `attributes`. `Ok(n)` is the count;
/// a locked match is [`Cause::Locked`] and nothing is removed.
///
/// # Errors
///
/// The sorted cause.
pub fn clear(ss: &SecretService<'_>, attributes: &[(&str, &str)]) -> Result<usize, Cause> {
    let attrs: HashMap<&str, &str> = attributes.iter().copied().collect();
    let found = ss.search_items(attrs).map_err(|e| sort(&e))?;
    if !found.locked.is_empty() {
        return Err(Cause::Locked("a matching item is locked".into()));
    }
    for item in &found.unlocked {
        item.delete().map_err(|e| sort(&e))?;
    }
    Ok(found.unlocked.len())
}

/// The value of attribute `key` on every item under `attributes`, locked
/// items included. Reads the `Attributes` property only: no secret.
///
/// # Errors
///
/// The sorted cause.
pub fn list_attribute(
    ss: &SecretService<'_>,
    attributes: &[(&str, &str)],
    key: &str,
) -> Result<Vec<String>, Cause> {
    let attrs: HashMap<&str, &str> = attributes.iter().copied().collect();
    let found = ss.search_items(attrs).map_err(|e| sort(&e))?;
    let mut out = Vec::new();
    for item in found.unlocked.iter().chain(found.locked.iter()) {
        let a = item.get_attributes().map_err(|e| sort(&e))?;
        if let Some(v) = a.get(key) {
            out.push(v.clone());
        }
    }
    out.sort();
    Ok(out)
}
