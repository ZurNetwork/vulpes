//! [`Did`] — the decentralized identifier newtype.
//!
//! A DID (`did:plc:…`, `did:web:…`) is the stable, self-sovereign identifier of
//! an actor on the AT Protocol network. vulpes both *recognizes* DIDs it is
//! handed (from a PDS at sign-in, from your own store) and *originates* them
//! (the [`Minter`](crate::Minter) derives a `did:plc` from the hash of a genesis
//! operation).

use std::borrow::Borrow;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize};

/// The scheme every DID starts with.
const DID_SCHEME: &str = "did:";

/// The `did:plc` method name.
const PLC_METHOD: &str = "plc";

/// A decentralized identifier.
///
/// Two ways in, deliberately:
///
/// - [`Did::new`] wraps a string the caller already trusts — one read back from
///   your own store, or handed over by a PDS at sign-in. No validation, because
///   re-validating a value the network already accepted can only reject data
///   that legitimately exists.
/// - [`FromStr`] / [`Deserialize`] **parse** untrusted input against the W3C DID
///   syntax (`did:<method-name>:<method-specific-id>`), and are what you want at
///   any boundary where a user or a remote peer supplies the string.
///
/// ```
/// use vulpes::Did;
///
/// let parsed: Did = "did:plc:ewvi7nxzyoun6zhxrhs64oiz".parse().unwrap();
/// assert_eq!(parsed.method(), Some("plc"));
/// assert!(parsed.is_plc());
///
/// // Not a DID at all.
/// assert!("https://example.com".parse::<Did>().is_err());
/// // A method name must be lowercase alphanumeric.
/// assert!("did:PLC:abc".parse::<Did>().is_err());
/// // Deserialization validates too — JSON is untrusted input.
/// assert!(serde_json::from_str::<Did>("\"not a did\"").is_err());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct Did(String);

/// Deserialization is a **parse**, not a wrapper.
///
/// A derived `Deserialize` would be `Did::new` with extra steps: every JSON
/// body, config file and cached record could produce a `Did` holding anything
/// at all, silently routing around the validation [`FromStr`] exists to
/// provide. Deserialization is where a value arrives from somewhere else, which
/// is precisely the untrusted boundary — so it parses.
///
/// The value still serializes as the bare string (`#[serde(transparent)]` on
/// the type), so the wire shape is unchanged in both directions: `"did:plc:…"`,
/// never a tuple wrapper.
///
/// Values already in your own store come in through [`Did::new`], which is
/// unchecked on purpose — see the type docs.
impl<'de> Deserialize<'de> for Did {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        raw.parse::<Self>().map_err(serde::de::Error::custom)
    }
}

/// Why a string was rejected as a [`Did`] by [`FromStr`].
///
/// The grammar checked is the W3C DID Core ABNF:
///
/// ```text
/// did                = "did:" method-name ":" method-specific-id
/// method-name        = 1*method-char
/// method-char        = %x61-7A / DIGIT
/// method-specific-id = *( *idchar ":" ) 1*idchar
/// idchar             = ALPHA / DIGIT / "." / "-" / "_" / pct-encoded
/// pct-encoded        = "%" HEXDIG HEXDIG
/// ```
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DidError {
    /// The string does not begin with the `did:` scheme.
    #[error("a DID must begin with `did:`")]
    MissingScheme,
    /// There is no `:` after the method name, so no method-specific id.
    #[error("a DID must have the form `did:<method>:<id>`")]
    MissingMethodSpecificId,
    /// The method name is empty or holds a character outside `[a-z0-9]`.
    #[error("`{0}` is not a valid DID method name (lowercase letters and digits only)")]
    InvalidMethodName(String),
    /// The method-specific id is empty, ends with `:`, or holds a character
    /// outside the `idchar` set.
    #[error("`{0}` is not a valid DID method-specific identifier")]
    InvalidMethodSpecificId(String),
}

impl Did {
    /// Wrap a DID the caller already trusts — read back from your own store, or
    /// handed over by a PDS at sign-in. Performs **no** validation; use
    /// [`FromStr`] for untrusted input.
    pub fn new(did: impl Into<String>) -> Self {
        Self(did.into())
    }

    /// The DID as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The method name (`plc` in `did:plc:abc`), or `None` if this value was
    /// built with [`Did::new`] from something that is not DID-shaped.
    pub fn method(&self) -> Option<&str> {
        let rest = self.0.strip_prefix(DID_SCHEME)?;
        let (method, id) = rest.split_once(':')?;
        (!method.is_empty() && !id.is_empty()).then_some(method)
    }

    /// Whether this is a `did:plc` — the method vulpes mints.
    pub fn is_plc(&self) -> bool {
        self.method() == Some(PLC_METHOD)
    }
}

impl FromStr for Did {
    type Err = DidError;
    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        let rest = raw
            .strip_prefix(DID_SCHEME)
            .ok_or(DidError::MissingScheme)?;
        let (method, id) = rest
            .split_once(':')
            .ok_or(DidError::MissingMethodSpecificId)?;

        let method_is_valid = !method.is_empty()
            && method
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
        if !method_is_valid {
            return Err(DidError::InvalidMethodName(method.to_owned()));
        }
        if !method_specific_id_is_valid(id) {
            return Err(DidError::InvalidMethodSpecificId(id.to_owned()));
        }
        Ok(Self(raw.to_owned()))
    }
}

/// Whether `id` matches `method-specific-id = *( *idchar ":" ) 1*idchar` — i.e.
/// colon-separated groups where the **last** group is non-empty and every
/// character is an `idchar` (ALPHA / DIGIT / `.` / `-` / `_` / pct-encoded).
fn method_specific_id_is_valid(id: &str) -> bool {
    let last_group_is_non_empty = id.rsplit(':').next().is_some_and(|last| !last.is_empty());
    last_group_is_non_empty && id.split(':').all(group_is_idchars)
}

/// Whether every character of one colon-separated group is an `idchar`,
/// treating `%HH` as a single percent-encoded unit.
fn group_is_idchars(group: &str) -> bool {
    let bytes = group.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'%' {
            let Some(pair) = bytes.get(index + 1..index + 3) else {
                return false;
            };
            if !pair.iter().all(u8::is_ascii_hexdigit) {
                return false;
            }
            index += 3;
            continue;
        }
        if !(byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_')) {
            return false;
        }
        index += 1;
    }
    true
}

impl fmt::Display for Did {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for Did {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Borrow<str> for Did {
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl From<Did> for String {
    fn from(did: Did) -> Self {
        did.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_plc_did() {
        let did = "did:plc:ewvi7nxzyoun6zhxrhs64oiz".parse::<Did>().unwrap();
        assert_eq!(did.method(), Some("plc"));
        assert!(did.is_plc());
        assert_eq!(did.as_str(), "did:plc:ewvi7nxzyoun6zhxrhs64oiz");
    }

    #[test]
    fn parses_a_web_did_with_colons_and_pct_encoding() {
        // `did:web` puts a percent-encoded host:port in the id, and the ABNF
        // allows interior colons — both must survive.
        let did = "did:web:example.com%3A8443:user:alice"
            .parse::<Did>()
            .unwrap();
        assert_eq!(did.method(), Some("web"));
        assert!(!did.is_plc());
    }

    #[test]
    fn rejects_a_non_did() {
        assert_eq!(
            "https://example.com".parse::<Did>(),
            Err(DidError::MissingScheme)
        );
        assert_eq!(
            "did:plc".parse::<Did>(),
            Err(DidError::MissingMethodSpecificId)
        );
    }

    #[test]
    fn rejects_a_bad_method_name() {
        // method-char is %x61-7A / DIGIT — uppercase and punctuation are out.
        assert_eq!(
            "did:PLC:abc".parse::<Did>(),
            Err(DidError::InvalidMethodName("PLC".into()))
        );
        assert_eq!(
            "did:pl-c:abc".parse::<Did>(),
            Err(DidError::InvalidMethodName("pl-c".into()))
        );
    }

    #[test]
    fn rejects_a_bad_method_specific_id() {
        // Empty, trailing-colon, out-of-charset, and truncated pct-encoding.
        assert!(matches!(
            "did:plc:".parse::<Did>(),
            Err(DidError::InvalidMethodSpecificId(_))
        ));
        assert!(matches!(
            "did:plc:abc:".parse::<Did>(),
            Err(DidError::InvalidMethodSpecificId(_))
        ));
        assert!(matches!(
            "did:plc:a b".parse::<Did>(),
            Err(DidError::InvalidMethodSpecificId(_))
        ));
        assert!(matches!(
            "did:plc:a%zz".parse::<Did>(),
            Err(DidError::InvalidMethodSpecificId(_))
        ));
        assert!(matches!(
            "did:plc:a%4".parse::<Did>(),
            Err(DidError::InvalidMethodSpecificId(_))
        ));
    }

    // `new` is the trusted-source door: it must never reject, so a value already
    // living in a store keeps round-tripping even if it predates this grammar.
    #[test]
    fn new_does_not_validate() {
        let odd = Did::new("not a did");
        assert_eq!(odd.as_str(), "not a did");
        assert_eq!(odd.method(), None);
        assert!(!odd.is_plc());
    }

    #[test]
    fn round_trips_through_the_std_conversions() {
        let did: Did = "did:plc:abc".parse().unwrap();
        assert_eq!(did.to_string(), "did:plc:abc");
        assert_eq!(AsRef::<str>::as_ref(&did), "did:plc:abc");
        assert_eq!(String::from(did.clone()), "did:plc:abc");
    }

    // The newtype serializes as the bare string (`#[serde(transparent)]`), so a
    // DID in a JSON payload is `"did:plc:…"`, never `{"0":"did:plc:…"}`. The
    // hand-written `Deserialize` must keep that wire shape.
    #[test]
    fn serializes_transparently() {
        let did = Did::new("did:plc:abc");
        assert_eq!(serde_json::to_string(&did).unwrap(), "\"did:plc:abc\"");
        assert_eq!(serde_json::from_str::<Did>("\"did:plc:abc\"").unwrap(), did);
    }

    // Deserialization is where a value arrives from somewhere else, so it
    // PARSES rather than wrapping. A derived impl would be `Did::new` with extra
    // steps, letting every JSON body route around the grammar `FromStr`
    // enforces — after which a `Did` proves nothing about its contents.
    #[test]
    fn deserialization_validates() {
        for hostile in [
            "\"not a did\"",
            "\"https://example.com\"",
            "\"did:PLC:abc\"",
            "\"did:plc:\"",
            "\"did:plc:a b\"",
            "\"\"",
        ] {
            assert!(
                serde_json::from_str::<Did>(hostile).is_err(),
                "{hostile} must not deserialize into a Did"
            );
        }

        // Every shape the grammar allows still round-trips.
        for valid in [
            "did:plc:ewvi7nxzyoun6zhxrhs64oiz",
            "did:web:example.com%3A8443:user:alice",
        ] {
            let json = format!("\"{valid}\"");
            let parsed: Did = serde_json::from_str(&json).expect("a valid DID deserializes");
            assert_eq!(parsed.as_str(), valid);
            assert_eq!(serde_json::to_string(&parsed).unwrap(), json);
        }
    }
}
