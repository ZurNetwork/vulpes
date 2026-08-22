//! [`Handle`] — a validated, normalized AT Protocol handle.
//!
//! A handle is the public, human-typeable name an actor is reached by, and the
//! back-link half of atproto's bidirectional handle verification: it appears in
//! a DID document's `alsoKnownAs` as `at://<handle>`, and resolves back to the
//! DID over DNS or HTTPS.
//!
//! This module enforces the **protocol** rules only — the atproto handle syntax
//! (charset, label and total length, reserved TLDs) plus the `xn--` punycode
//! reject. It deliberately holds **no product policy**: reserved-label
//! namespaces ("you may not register `admin.example.com`"), rate limits and
//! quarantine windows are your application's business, layered on top of a
//! `Handle` that already parsed.
//!
//! Spec: <https://atproto.com/specs/handle>.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize};

/// The longest a whole handle may be, in `char`s (atproto handle syntax).
pub const HANDLE_MAX_LEN: usize = 253;

/// The longest a single handle label (dot-separated segment) may be.
pub const LABEL_MAX_LEN: usize = 63;

/// The punycode/IDN label prefix, rejected outright — see [`HandleError::PunycodeLabel`].
const PUNYCODE_PREFIX: &str = "xn--";

/// Top-level domains the atproto handle spec forbids as handles: special-use
/// names that either resolve locally or must never resolve at all.
pub(crate) const RESERVED_TLDS: &[&str] = &[
    "alt",
    "arpa",
    "example",
    "internal",
    "invalid",
    "local",
    "localhost",
    "onion",
    "test",
];

/// A validated, normalized AT Protocol handle.
///
/// Validate on the way in, then read the normalized form back with
/// [`Handle::as_str`] — always lowercase, trimmed, and without a trailing dot.
///
/// ```
/// use vulpes::Handle;
///
/// // Normalized: trimmed, lowercased, trailing FQDN dot stripped.
/// let handle: Handle = "  Alice.Example.COM.  ".parse().unwrap();
/// assert_eq!(handle.as_str(), "alice.example.com");
///
/// // Punycode labels are rejected outright — the homoglyph-IDN vector.
/// assert!("xn--80ak6aa92e.example.com".parse::<Handle>().is_err());
///
/// // Special-use TLDs are not handles.
/// assert!("alice.local".parse::<Handle>().is_err());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct Handle(String);

/// Deserialization is a **parse**, not a wrapper — and here that is a security
/// boundary, not just tidiness.
///
/// A `Handle` is what [`Authenticator::start`](crate::oauth::Authenticator::start)
/// takes *instead of* a string, precisely so the resolver's
/// "an input beginning `https://` is a service URL, fetch it directly" branch
/// cannot be reached. That guarantee is only worth anything if **every** door
/// into the type validates. A derived `Deserialize` is not a door that
/// validates: it would hand back a `Handle` holding
/// `https://169.254.169.254/…` straight from a JSON login body — the single
/// most likely way a handle actually arrives — and walk it right into the fetch
/// the type exists to prevent.
///
/// So this parses, and the value that comes out is normalized exactly as
/// [`Handle::try_new`] normalizes: trimmed, lowercased, no trailing dot. It
/// serializes as the bare string, so the wire shape is unchanged.
impl<'de> Deserialize<'de> for Handle {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::try_new(raw).map_err(serde::de::Error::custom)
    }
}

/// Why a string was rejected as a [`Handle`]. One variant per failure class, so
/// a caller can map each to its own message or problem type.
///
/// ```
/// use vulpes::{Handle, HandleError};
///
/// assert_eq!("".parse::<Handle>(), Err(HandleError::Empty));
/// assert_eq!("alice".parse::<Handle>(), Err(HandleError::TooFewSegments));
/// assert_eq!(
///     "foo.local".parse::<Handle>(),
///     Err(HandleError::ReservedTld("local".into())),
/// );
/// ```
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HandleError {
    /// Empty once normalized. Example: `""`, `"   "`, or `"."`.
    #[error("handle must not be empty")]
    Empty,
    /// Longer than [`HANDLE_MAX_LEN`] chars overall. Carries the offending length.
    #[error("handle is {0} chars; the max is {HANDLE_MAX_LEN}")]
    TooLong(usize),
    /// Fewer than two dot-separated segments (e.g. a bare `"alice"`).
    #[error("handle must have at least two segments (e.g. `alice.example.com`)")]
    TooFewSegments,
    /// A dot-separated segment is empty (e.g. `"alice..com"`).
    #[error("handle has an empty segment")]
    EmptySegment,
    /// A segment is longer than [`LABEL_MAX_LEN`] chars. Carries the length.
    #[error("handle segment is {0} chars; the max is {LABEL_MAX_LEN}")]
    SegmentTooLong(usize),
    /// A character outside the `[a-z0-9-]` charset. Carries the offending char.
    #[error("handle contains an invalid character {0:?}; only a-z, 0-9, and '-' are allowed")]
    InvalidChar(char),
    /// A segment starts or ends with a hyphen.
    #[error("a handle segment must not start or end with a hyphen")]
    HyphenEdge,
    /// The rightmost (top-level) segment starts with a digit.
    #[error("the rightmost handle segment must not start with a digit")]
    TldLeadingDigit,
    /// The rightmost segment is a special-use TLD (`.local`, `.test`, …).
    #[error("`.{0}` is a reserved top-level domain and cannot be a handle")]
    ReservedTld(String),
    /// Some label begins with `xn--` (punycode).
    ///
    /// Rejected in full: a punycode label decodes to non-ASCII text whose
    /// rendered glyphs can be visually identical to another handle's, which
    /// turns the handle namespace into an impersonation surface. Allowing IDN
    /// safely needs a UTS #39 confusable-detection pass, which this crate does
    /// not (yet) do — so the conservative reject is the whole policy.
    #[error("punycode (`xn--`) handle labels are not allowed")]
    PunycodeLabel,
}

impl Handle {
    /// Validate and wrap a handle, enforcing every rule in one pass.
    ///
    /// The input is first **normalized** — surrounding whitespace trimmed,
    /// lowercased, a single trailing FQDN dot stripped — and then checked, in
    /// order:
    ///
    /// 1. non-empty and at most [`HANDLE_MAX_LEN`] chars;
    /// 2. at least two dot-separated segments, none empty;
    /// 3. each segment at most [`LABEL_MAX_LEN`] chars, no leading or trailing
    ///    hyphen, every char in `[a-z0-9-]`;
    /// 4. no label begins with `xn--`;
    /// 5. the rightmost segment does not start with a digit;
    /// 6. the rightmost segment is not a reserved TLD.
    ///
    /// [`FromStr`] and both [`TryFrom`] impls delegate here; prefer those at
    /// call sites. This inherent constructor exists because it can take an
    /// owned `String` without a second allocation.
    ///
    /// ```
    /// use vulpes::{Handle, HandleError};
    ///
    /// assert_eq!(Handle::try_new("alice.example.com").unwrap().as_str(), "alice.example.com");
    /// // Case-insensitive: the input is lowercased before the punycode check.
    /// assert_eq!(Handle::try_new("XN--abc.com"), Err(HandleError::PunycodeLabel));
    /// ```
    pub fn try_new(raw: impl Into<String>) -> Result<Self, HandleError> {
        // 1. NORMALIZE: trim, lowercase, strip a single trailing dot (FQDN root).
        let lowered = raw.into().trim().to_lowercase();
        let normalized = lowered.strip_suffix('.').unwrap_or(&lowered).to_owned();

        // 2. Overall length.
        if normalized.is_empty() {
            return Err(HandleError::Empty);
        }
        let len = normalized.chars().count();
        if len > HANDLE_MAX_LEN {
            return Err(HandleError::TooLong(len));
        }

        // 3. Segments: at least two, none empty.
        let labels: Vec<&str> = normalized.split('.').collect();
        if labels.len() < 2 {
            return Err(HandleError::TooFewSegments);
        }
        if labels.iter().any(|label| label.is_empty()) {
            return Err(HandleError::EmptySegment);
        }

        // 4. Per-label charset / length / hyphen-edge, checked on EVERY label
        //    before any punycode rejection — so a malformed label reports its
        //    real fault rather than a misleading one.
        for label in &labels {
            let label_len = label.chars().count();
            if label_len > LABEL_MAX_LEN {
                return Err(HandleError::SegmentTooLong(label_len));
            }
            if label.starts_with('-') || label.ends_with('-') {
                return Err(HandleError::HyphenEdge);
            }
            if let Some(bad) = label
                .chars()
                .find(|&c| !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'))
            {
                return Err(HandleError::InvalidChar(bad));
            }
        }

        // 5. Punycode reject, on any label. The value is already lowercased, so
        //    a plain prefix check is case-insensitive.
        if labels
            .iter()
            .any(|label| label.starts_with(PUNYCODE_PREFIX))
        {
            return Err(HandleError::PunycodeLabel);
        }

        // 6. The rightmost (top-level) segment must not start with a digit.
        let tld = *labels.last().expect("at least two labels checked above");
        if tld.chars().next().is_some_and(|c| c.is_ascii_digit()) {
            return Err(HandleError::TldLeadingDigit);
        }

        // 7. Reserved (special-use) TLDs.
        if RESERVED_TLDS.contains(&tld) {
            return Err(HandleError::ReservedTld(tld.to_owned()));
        }

        Ok(Self(normalized))
    }

    /// The normalized handle (lowercase, trimmed, no trailing dot).
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The `at://<handle>` URI this handle contributes to a DID document's
    /// `alsoKnownAs`.
    ///
    /// ```
    /// # use vulpes::Handle;
    /// let handle = Handle::try_new("alice.example.com").unwrap();
    /// assert_eq!(handle.at_uri(), "at://alice.example.com");
    /// ```
    pub fn at_uri(&self) -> String {
        format!("at://{}", self.0)
    }
}

impl FromStr for Handle {
    type Err = HandleError;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        Self::try_new(raw)
    }
}

impl TryFrom<&str> for Handle {
    type Error = HandleError;

    fn try_from(raw: &str) -> Result<Self, Self::Error> {
        Self::try_new(raw)
    }
}

impl TryFrom<String> for Handle {
    type Error = HandleError;

    fn try_from(raw: String) -> Result<Self, Self::Error> {
        Self::try_new(raw)
    }
}

impl fmt::Display for Handle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for Handle {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl From<Handle> for String {
    fn from(handle: Handle) -> Self {
        handle.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Normalization -----------------------------------------------------

    #[test]
    fn lowercases_the_handle() {
        assert_eq!(
            Handle::try_new("Alice.Example.COM").unwrap().as_str(),
            "alice.example.com"
        );
    }

    #[test]
    fn strips_a_single_trailing_dot() {
        assert_eq!(
            Handle::try_new("alice.example.com.").unwrap().as_str(),
            "alice.example.com"
        );
    }

    #[test]
    fn trims_surrounding_whitespace() {
        assert_eq!(
            Handle::try_new("  alice.example.com  ").unwrap().as_str(),
            "alice.example.com"
        );
    }

    // ---- Charset / segment / length ---------------------------------------

    #[test]
    fn rejects_a_single_segment() {
        assert_eq!(Handle::try_new("alice"), Err(HandleError::TooFewSegments));
    }

    #[test]
    fn rejects_an_empty_input() {
        assert_eq!(Handle::try_new("   "), Err(HandleError::Empty));
        assert_eq!(Handle::try_new("."), Err(HandleError::Empty));
    }

    #[test]
    fn rejects_an_empty_segment() {
        assert_eq!(
            Handle::try_new("alice..com"),
            Err(HandleError::EmptySegment)
        );
    }

    #[test]
    fn rejects_a_segment_over_63_chars() {
        let long_label = "a".repeat(64);
        assert_eq!(
            Handle::try_new(format!("{long_label}.com")),
            Err(HandleError::SegmentTooLong(64))
        );
    }

    #[test]
    fn rejects_a_handle_over_253_chars() {
        // Built out of legal 63-char labels: 4*63 + 3 dots + ".com" = 259.
        let label = "a".repeat(63);
        let raw = format!("{label}.{label}.{label}.{label}.com");
        let len = raw.chars().count();
        assert_eq!(Handle::try_new(raw), Err(HandleError::TooLong(len)));
    }

    #[test]
    fn rejects_a_leading_or_trailing_hyphen() {
        assert_eq!(Handle::try_new("-alice.com"), Err(HandleError::HyphenEdge));
        assert_eq!(Handle::try_new("alice-.com"), Err(HandleError::HyphenEdge));
    }

    #[test]
    fn rejects_out_of_charset_bytes() {
        assert_eq!(
            Handle::try_new("ali_ce.com"),
            Err(HandleError::InvalidChar('_'))
        );
        assert_eq!(
            Handle::try_new("ali ce.com"),
            Err(HandleError::InvalidChar(' '))
        );
        assert_eq!(
            Handle::try_new("café.com"),
            Err(HandleError::InvalidChar('é'))
        );
    }

    #[test]
    fn rejects_a_digit_leading_tld() {
        assert_eq!(
            Handle::try_new("alice.123"),
            Err(HandleError::TldLeadingDigit)
        );
    }

    // ---- Reserved TLDs -----------------------------------------------------

    #[test]
    fn rejects_every_reserved_tld() {
        for tld in RESERVED_TLDS {
            assert_eq!(
                Handle::try_new(format!("foo.{tld}")),
                Err(HandleError::ReservedTld((*tld).to_owned())),
                "`.{tld}` must not be a handle"
            );
        }
    }

    // ---- Punycode ----------------------------------------------------------

    #[test]
    fn rejects_punycode_anywhere_and_mixed_case() {
        assert_eq!(
            Handle::try_new("xn--80ak6aa92e.example.com"),
            Err(HandleError::PunycodeLabel)
        );
        // Not just the leftmost label.
        assert_eq!(
            Handle::try_new("good.xn--abc.com"),
            Err(HandleError::PunycodeLabel)
        );
        // Mixed-case `XN--` is normalized, then caught.
        assert_eq!(
            Handle::try_new("XN--abc.com"),
            Err(HandleError::PunycodeLabel)
        );
    }

    // ---- No product policy -------------------------------------------------

    // The deliberate line: vulpes enforces the protocol, never a namespace
    // policy. Words an application might reserve (`admin`, `api`, its own
    // brand) are perfectly valid handles here.
    #[test]
    fn holds_no_reserved_label_policy() {
        for raw in ["admin.example.com", "api.example.com", "www.example.com"] {
            assert!(
                Handle::try_new(raw).is_ok(),
                "{raw} is protocol-valid; reserving it is the application's job"
            );
        }
    }

    // ---- Happy path + std traits ------------------------------------------

    #[test]
    fn accepts_well_formed_handles_through_every_door() {
        let parsed: Handle = "alice.example.com".parse().unwrap();
        assert_eq!(parsed.as_str(), "alice.example.com");
        assert_eq!(Handle::try_from("alice.example.com").unwrap(), parsed);
        assert_eq!(
            Handle::try_from("alice.example.com".to_string()).unwrap(),
            parsed
        );
        assert_eq!(parsed.to_string(), "alice.example.com");
        assert_eq!(AsRef::<str>::as_ref(&parsed), "alice.example.com");
        assert_eq!(String::from(parsed.clone()), "alice.example.com");
    }

    #[test]
    fn renders_the_at_uri_for_also_known_as() {
        let handle = Handle::try_new("alice.example.com").unwrap();
        assert_eq!(handle.at_uri(), "at://alice.example.com");
    }

    // THE SSRF DOOR. `Authenticator::start` takes a `Handle` instead of a
    // string so the resolver's fetch-this-service-URL branch is unreachable —
    // which is only true if EVERY way of getting a `Handle` validates.
    // Deserialization is the likeliest way one actually arrives (a JSON login
    // body), so it must parse, not wrap.
    #[test]
    fn deserialization_validates() {
        for hostile in [
            "\"https://169.254.169.254/latest/meta-data/\"",
            "\"https://alice.example.com\"",
            "\"http://127.0.0.1:8080/\"",
            "\"xn--80ak6aa92e.example.com\"",
            "\"alice.local\"",
            "\"alice\"",
            "\"\"",
            "\"alice..com\"",
        ] {
            assert!(
                serde_json::from_str::<Handle>(hostile).is_err(),
                "{hostile} must not deserialize into a Handle"
            );
        }
    }

    // Deserialization normalizes exactly as `try_new` does, and the value still
    // serializes as the bare string — the wire shape is unchanged in both
    // directions.
    #[test]
    fn deserialization_normalizes_and_round_trips() {
        let handle: Handle =
            serde_json::from_str("\"  Alice.Example.COM.  \"").expect("a valid handle");
        assert_eq!(handle.as_str(), "alice.example.com");
        assert_eq!(
            serde_json::to_string(&handle).unwrap(),
            "\"alice.example.com\""
        );
    }

    #[test]
    fn every_error_variant_renders_a_message() {
        let variants = [
            HandleError::Empty,
            HandleError::TooLong(300),
            HandleError::TooFewSegments,
            HandleError::EmptySegment,
            HandleError::SegmentTooLong(64),
            HandleError::InvalidChar('_'),
            HandleError::HyphenEdge,
            HandleError::TldLeadingDigit,
            HandleError::ReservedTld("local".into()),
            HandleError::PunycodeLabel,
        ];
        for variant in variants {
            assert!(
                !variant.to_string().is_empty(),
                "{variant:?} rendered an empty message"
            );
        }
    }
}
