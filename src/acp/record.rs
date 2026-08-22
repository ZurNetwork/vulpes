//! The three ACP record types and their canonical bytes.
//!
//! Field names and shapes follow the lexicons under `lexicons/` exactly.
//! Everything here serializes through [`canonical_bytes`] — DAG-CBOR, which
//! `serde_ipld_dagcbor` emits with map keys sorted length-first-then-bytewise
//! **regardless of struct field order** (it buffers every entry and sorts;
//! see FORKS F35 for why this must never be an implicit property).
//!
//! Conventions that are load-bearing for byte stability:
//!
//! - optional fields are **absent**, never `null` (`skip_serializing_if`);
//! - `sig` is a CBOR byte string (major type 2), via `serde_bytes`;
//! - a strongRef's `cid` is a **text string** (`bafyrei…`), as
//!   `com.atproto.repo.strongRef` defines it — not a tag-42 link;
//! - datetimes are RFC 3339 strings; no integers wider than 53 bits, no
//!   floats, no `null` anywhere (the atproto data model).

use std::fmt;
use std::str::FromStr;

use serde::de::{self, Deserializer};
use serde::{Deserialize, Serialize};

use crate::Did;

use super::error::CodecError;

/// NSID of the self-claim record.
pub const CLAIM_TYPE: &str = "net.got-paws.acp.claim";
/// NSID of the attestation record.
pub const ATTESTATION_TYPE: &str = "net.got-paws.acp.attestation";
/// NSID of the mutual-claim (relationship) record.
pub const RELATIONSHIP_TYPE: &str = "net.got-paws.acp.relationship";
/// NSID of the status-list artifact (see [`super::status`]).
pub const STATUS_LIST_TYPE: &str = "net.got-paws.acp.statusList";

// ─── canonical bytes ────────────────────────────────────────────────────────

/// Encode `value` as canonical DAG-CBOR.
///
/// One helper so every hash and signature in the ACP core goes through the
/// same call (mirrors `plc::dag_cbor`).
pub fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, CodecError> {
    serde_ipld_dagcbor::to_vec(value).map_err(|err| CodecError::Encode(err.to_string()))
}

/// Decode a record from DAG-CBOR bytes.
pub fn from_canonical_bytes<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, CodecError> {
    serde_ipld_dagcbor::from_slice(bytes).map_err(|err| CodecError::Decode(err.to_string()))
}

/// A CIDv1 (`dag-cbor`, `sha2-256`) of some canonical bytes — the content
/// identity a strongRef points at, and the thing an attestor signs.
///
/// The same construction as a PLC operation's CID ([`crate::plc::cid_bytes`]),
/// kept as bytes here because the signature goes over the raw CID bytes (the
/// CID-First Attestation construction). On the wire — in a strongRef — it is
/// the multibase text form, `bafyrei…`, exactly as `com.atproto.repo.strongRef`
/// defines it (FORKS F37), so it serializes as a string and parses from one.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RecordCid([u8; 36]);

impl RecordCid {
    /// Hash `canonical` (already DAG-CBOR) into its CID.
    pub fn of(canonical: &[u8]) -> Self {
        Self(crate::plc::cid_bytes(canonical))
    }

    /// Parse the multibase text form (`bafyrei…`); only the CIDv1 dag-cbor
    /// sha2-256 shape this crate produces is accepted.
    pub fn parse(raw: &str) -> Result<Self, CodecError> {
        let err = |detail: &str| CodecError::InvalidField {
            field: "cid",
            detail: detail.to_string(),
        };
        let body = raw
            .strip_prefix('b')
            .ok_or_else(|| err("expected multibase base32 (`b…`)"))?;
        let decoded = data_encoding::BASE32_NOPAD
            .decode(body.to_ascii_uppercase().as_bytes())
            .map_err(|e| err(&e.to_string()))?;
        let bytes: [u8; 36] = decoded
            .try_into()
            .map_err(|_| err("expected 36 bytes (CIDv1 + sha2-256 multihash)"))?;
        if bytes[..4] != [0x01, 0x71, 0x12, 0x20] {
            return Err(err("expected CIDv1 dag-cbor sha2-256"));
        }
        Ok(Self(bytes))
    }

    /// The raw CID bytes (36: 4-byte prefix + 32-byte digest).
    pub fn as_bytes(&self) -> &[u8; 36] {
        &self.0
    }
}

impl fmt::Display for RecordCid {
    /// multibase `b` (base32 lowercase, no padding): `bafyrei…`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&crate::plc::cid_string(&self.0))
    }
}

impl FromStr for RecordCid {
    type Err = CodecError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl TryFrom<&str> for RecordCid {
    type Error = CodecError;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::parse(s)
    }
}

impl TryFrom<String> for RecordCid {
    type Error = CodecError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::parse(&s)
    }
}

impl Serialize for RecordCid {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for RecordCid {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Self::parse(&String::deserialize(d)?).map_err(de::Error::custom)
    }
}

impl fmt::Debug for RecordCid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RecordCid({self})")
    }
}

// ─── `$type` markers ────────────────────────────────────────────────────────

macro_rules! type_marker {
    ($(#[$doc:meta])* $name:ident = $nsid:expr) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct $name;

        impl ::serde::Serialize for $name {
            fn serialize<S: ::serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str($nsid)
            }
        }

        impl<'de> ::serde::Deserialize<'de> for $name {
            fn deserialize<D: ::serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let raw = <String as ::serde::Deserialize>::deserialize(d)?;
                if raw == $nsid {
                    Ok(Self)
                } else {
                    Err(<D::Error as ::serde::de::Error>::custom(format!(
                        "expected $type {:?}, found {:?}",
                        $nsid, raw
                    )))
                }
            }
        }
    };
}

pub(crate) use type_marker;

type_marker!(
    /// The `$type` of a [`Claim`]: serializes as [`CLAIM_TYPE`], refuses anything else.
    ClaimType = CLAIM_TYPE
);
type_marker!(
    /// The `$type` of an [`Attestation`]: serializes as [`ATTESTATION_TYPE`].
    AttestationType = ATTESTATION_TYPE
);
type_marker!(
    /// The `$type` of a [`Relationship`]: serializes as [`RELATIONSHIP_TYPE`].
    RelationshipType = RELATIONSHIP_TYPE
);

// ─── scalar newtypes ────────────────────────────────────────────────────────

/// An RFC 3339 datetime string, syntax-checked on construction.
///
/// Held as the string it arrived as — the bytes are what gets signed, so the
/// value is never re-rendered through a date library.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct Datetime(String);

impl Datetime {
    /// Accept `YYYY-MM-DDTHH:MM:SS[.fraction](Z|±HH:MM)` with every field in
    /// range (month 1–12, day valid for that month and leap year, hour ≤ 23,
    /// minute ≤ 59, second ≤ 60 for a leap second, offset ≤ ±23:59).
    ///
    /// Syntax *and* calendar: a value that passes here means the same
    /// instant to this crate's [`to_unix`](Self::to_unix), to chrono, and
    /// to Postgres, so a verifier never compares a nonsense number.
    pub fn parse(raw: &str) -> Result<Self, CodecError> {
        fn err(detail: &str) -> CodecError {
            CodecError::InvalidField {
                field: "datetime",
                detail: detail.to_string(),
            }
        }
        let b = raw.as_bytes();
        let digits = |range: std::ops::Range<usize>| {
            b.get(range)
                .is_some_and(|s| s.iter().all(u8::is_ascii_digit))
        };
        let at = |i: usize, c: u8| b.get(i) == Some(&c);
        if !(digits(0..4) && at(4, b'-') && digits(5..7) && at(7, b'-') && digits(8..10)) {
            return Err(err("expected YYYY-MM-DD"));
        }
        if !(at(10, b'T') || at(10, b't')) {
            return Err(err("expected 'T' date/time separator"));
        }
        if !(digits(11..13) && at(13, b':') && digits(14..16) && at(16, b':') && digits(17..19)) {
            return Err(err("expected HH:MM:SS"));
        }
        let num = |r: std::ops::Range<usize>| -> u32 {
            std::str::from_utf8(&b[r])
                .unwrap_or("0")
                .parse()
                .unwrap_or(0)
        };
        let (y, m, d) = (num(0..4), num(5..7), num(8..10));
        if !(1..=12).contains(&m) {
            return Err(err("month out of range"));
        }
        let leap = y.is_multiple_of(4) && (!y.is_multiple_of(100) || y.is_multiple_of(400));
        let days_in_month = match m {
            1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
            4 | 6 | 9 | 11 => 30,
            _ if leap => 29,
            _ => 28,
        };
        if !(1..=days_in_month).contains(&d) {
            return Err(err("day out of range for month"));
        }
        let (hh, mm, ss) = (num(11..13), num(14..16), num(17..19));
        if hh > 23 || mm > 59 || ss > 60 {
            return Err(err("time of day out of range"));
        }
        let mut i = 19;
        if at(i, b'.') {
            let start = i + 1;
            i = start;
            while i < b.len() && b[i].is_ascii_digit() {
                i += 1;
            }
            if i == start {
                return Err(err("empty fractional seconds"));
            }
        }
        match b.get(i) {
            Some(b'Z') | Some(b'z') if i + 1 == b.len() => {}
            Some(b'+') | Some(b'-')
                if digits(i + 1..i + 3)
                    && at(i + 3, b':')
                    && digits(i + 4..i + 6)
                    && i + 6 == b.len() =>
            {
                if num(i + 1..i + 3) > 23 || num(i + 4..i + 6) > 59 {
                    return Err(err("offset out of range"));
                }
            }
            _ => return Err(err("expected 'Z' or ±HH:MM offset")),
        }
        Ok(Self(raw.to_string()))
    }

    /// The string form.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Seconds since the Unix epoch, offset applied, fraction truncated.
    ///
    /// Hand-rolled (days-from-civil; FORKS F41) so the pure lane compares
    /// expiry without a date library; syntax and ranges were already checked
    /// by [`Datetime::parse`], so the slices below cannot fail. Truncation
    /// means two instants in the same second compare equal — callers that
    /// must order them (the newest-status-list pick) break the tie on
    /// content, never on arrival order.
    pub fn to_unix(&self) -> i64 {
        let b = self.0.as_bytes();
        let num = |r: std::ops::Range<usize>| -> i64 {
            std::str::from_utf8(&b[r])
                .unwrap_or("0")
                .parse()
                .unwrap_or(0)
        };
        let (y, m, d) = (num(0..4), num(5..7), num(8..10));
        let (hh, mm, ss) = (num(11..13), num(14..16), num(17..19));
        // Howard Hinnant's days_from_civil.
        let y = if m <= 2 { y - 1 } else { y };
        let era = if y >= 0 { y } else { y - 399 } / 400;
        let yoe = y - era * 400;
        let mp = (m + 9) % 12;
        let doy = (153 * mp + 2) / 5 + d - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        let days = era * 146_097 + doe - 719_468;
        let mut secs = days * 86_400 + hh * 3_600 + mm * 60 + ss;
        // Offset: the tail is `Z` or `±HH:MM`; local = UTC + offset.
        let tail = &self.0[self.0.len() - 6..];
        if let Some(sign) = tail.chars().next().filter(|c| *c == '+' || *c == '-') {
            let oh: i64 = tail[1..3].parse().unwrap_or(0);
            let om: i64 = tail[4..6].parse().unwrap_or(0);
            let off = oh * 3_600 + om * 60;
            secs -= if sign == '+' { off } else { -off };
        }
        secs
    }

    /// Nanoseconds since the Unix epoch — [`to_unix`](Self::to_unix) plus
    /// the fractional second, so two instants inside one second order
    /// correctly (the newest-status-list pick needs this: a revoking list
    /// at `.900` must beat a clear one at `.100`). Digits past the ninth
    /// are ignored.
    pub fn to_unix_nanos(&self) -> i128 {
        let b = self.0.as_bytes();
        let mut nanos: i128 = 0;
        if b.get(19) == Some(&b'.') {
            let mut scale: i128 = 100_000_000;
            for d in b[20..].iter().take_while(|d| d.is_ascii_digit()).take(9) {
                nanos += i128::from(d - b'0') * scale;
                scale /= 10;
            }
        }
        i128::from(self.to_unix()) * 1_000_000_000 + nanos
    }
}

impl<'de> Deserialize<'de> for Datetime {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Self::parse(&String::deserialize(d)?).map_err(de::Error::custom)
    }
}

impl FromStr for Datetime {
    type Err = CodecError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl TryFrom<&str> for Datetime {
    type Error = CodecError;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::parse(s)
    }
}

impl TryFrom<String> for Datetime {
    type Error = CodecError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::parse(&s)
    }
}

impl fmt::Display for Datetime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// An `at://` URI naming a record: `at://<did-or-handle>/<collection>/<rkey>`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct AtUri(String);

impl AtUri {
    /// Syntax check: scheme, non-empty authority, no whitespace. Whether the
    /// authority is a DID or a handle, and whether the path is complete, is
    /// the fetch layer's concern.
    pub fn parse(raw: &str) -> Result<Self, CodecError> {
        let err = |detail: &str| CodecError::InvalidField {
            field: "at-uri",
            detail: detail.to_string(),
        };
        let rest = raw
            .strip_prefix("at://")
            .ok_or_else(|| err("must start with at://"))?;
        let authority = rest.split('/').next().unwrap_or("");
        if authority.is_empty() {
            return Err(err("missing authority"));
        }
        if raw.chars().any(char::is_whitespace) {
            return Err(err("contains whitespace"));
        }
        Ok(Self(raw.to_string()))
    }

    /// The string form.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The authority: a DID or a handle.
    pub fn authority(&self) -> &str {
        self.0["at://".len()..].split('/').next().unwrap_or("")
    }

    /// The collection NSID, when the path has one.
    pub fn collection(&self) -> Option<&str> {
        self.0["at://".len()..]
            .split('/')
            .nth(1)
            .filter(|s| !s.is_empty())
    }

    /// The record key, when the path has one.
    pub fn rkey(&self) -> Option<&str> {
        self.0["at://".len()..]
            .split('/')
            .nth(2)
            .filter(|s| !s.is_empty())
    }

    /// Build `at://<repo>/<collection>/<rkey>`.
    pub fn record(repo: &Did, collection: &str, rkey: &str) -> Self {
        Self(format!("at://{}/{collection}/{rkey}", repo.as_str()))
    }
}

impl<'de> Deserialize<'de> for AtUri {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Self::parse(&String::deserialize(d)?).map_err(de::Error::custom)
    }
}

impl FromStr for AtUri {
    type Err = CodecError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl TryFrom<&str> for AtUri {
    type Error = CodecError;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::parse(s)
    }
}

impl TryFrom<String> for AtUri {
    type Error = CodecError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::parse(&s)
    }
}

impl fmt::Display for AtUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The attestor's signature: raw bytes, a CBOR byte string on the wire.
///
/// For the atproto profile this is the 64-byte compact `r‖s` ECDSA signature
/// (low-S). Rendered base64url in JSON views; this type does not do that.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Sig(#[serde(with = "serde_bytes")] pub Vec<u8>);

impl fmt::Debug for Sig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sig({} bytes)", self.0.len())
    }
}

/// `com.atproto.repo.strongRef`: a record address plus the CID of the exact
/// content it had — the binding that makes "attest the new version or live
/// without" real.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StrongRef {
    /// Where the record lives.
    pub uri: AtUri,
    /// The CID of its content — a text string (`bafyrei…`) on the wire.
    pub cid: RecordCid,
}

impl StrongRef {
    /// Point at `uri` holding content whose canonical bytes hash to `cid`.
    pub fn new(uri: AtUri, cid: &RecordCid) -> Self {
        Self { uri, cid: *cid }
    }
}

/// The address of a status-list artifact — `status.list` — validated at
/// the boundary so a verifier can never be pointed at something it must not
/// fetch.
///
/// This is attacker-influenced input: anyone can write an attestation with
/// any `status.list` into their own repo. The rules (FORKS F29 precedent —
/// unreachable by construction, not by a check that can be forgotten):
/// `https` only; a DNS host, never an IP literal (which removes loopback,
/// link-local and private ranges in one stroke) and never `localhost`; no
/// userinfo; no whitespace. DNS rebinding is the egress guard's concern —
/// the HTTP `StatusSource` should accept an injected client for exactly
/// that. The same string is the list's identifier (see
/// [`UnsignedStatusList::list`](super::status::UnsignedStatusList::list)).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct StatusUri(String);

impl StatusUri {
    /// Accept `https://<dns-host>[:port]/…` and nothing else.
    pub fn parse(raw: &str) -> Result<Self, CodecError> {
        let err = |detail: &str| CodecError::InvalidField {
            field: "status.list",
            detail: detail.to_string(),
        };
        if raw.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err(err("contains whitespace or control characters"));
        }
        let rest = raw
            .strip_prefix("https://")
            .ok_or_else(|| err("must start with https://"))?;
        let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
        if authority.contains('@') {
            return Err(err("userinfo is not allowed"));
        }
        if authority.starts_with('[') {
            return Err(err("IP literals are not allowed"));
        }
        let host = authority.rsplit_once(':').map_or(authority, |(h, port)| {
            if port.chars().all(|c| c.is_ascii_digit()) {
                h
            } else {
                authority
            }
        });
        if host.is_empty() {
            return Err(err("missing host"));
        }
        if host.eq_ignore_ascii_case("localhost")
            || host.to_ascii_lowercase().ends_with(".localhost")
        {
            return Err(err("localhost is not allowed"));
        }
        let looks_like_ipv4 = host
            .split('.')
            .all(|l| !l.is_empty() && l.chars().all(|c| c.is_ascii_digit()));
        if looks_like_ipv4 {
            return Err(err("IP literals are not allowed"));
        }
        if !host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
        {
            return Err(err("host must be a DNS name"));
        }
        Ok(Self(raw.to_string()))
    }

    /// The string form.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for StatusUri {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Self::parse(&String::deserialize(d)?).map_err(de::Error::custom)
    }
}

impl fmt::Display for StatusUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for StatusUri {
    type Err = CodecError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl TryFrom<&str> for StatusUri {
    type Error = CodecError;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::parse(s)
    }
}

impl TryFrom<String> for StatusUri {
    type Error = CodecError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::parse(&s)
    }
}

/// Where an attestation's revocation bit lives.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StatusRef {
    /// The signed status-list artifact's identifier and address (any mirror
    /// may serve it). Validated: see [`StatusUri`].
    pub list: StatusUri,
    /// Bit index of this attestation in that list.
    pub index: u64,
}

// ─── kinds ──────────────────────────────────────────────────────────────────

macro_rules! string_enum {
    ($(#[$doc:meta])* $name:ident { $($(#[$vdoc:meta])* $variant:ident = $s:expr),+ $(,)? }) => {
        $(#[$doc])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        pub enum $name {
            $($(#[$vdoc])* $variant,)+
            /// A kind this build does not know. Round-trips untouched; a
            /// verifier ignores records of unknown kind rather than rejecting
            /// the repo (forward compatibility).
            Unknown(String),
        }

        impl $name {
            /// The wire string.
            pub fn as_str(&self) -> &str {
                match self {
                    $(Self::$variant => $s,)+
                    Self::Unknown(s) => s,
                }
            }
        }

        impl From<&str> for $name {
            fn from(s: &str) -> Self {
                match s {
                    $($s => Self::$variant,)+
                    other => Self::Unknown(other.to_string()),
                }
            }
        }

        impl Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str(self.as_str())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                Ok(Self::from(String::deserialize(d)?.as_str()))
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.as_str())
            }
        }
    };
}

string_enum!(
    /// A self-claim's kind, from the published catalog (v0.1 seeds).
    ClaimKind {
        /// Control of an email address; `payload.address`.
        Email = "email",
        /// An account on another service.
        ExternalAccount = "external-account",
        /// A character the subject presents.
        Character = "character",
    }
);

string_enum!(
    /// A relationship half's kind, from the published catalog (v0.1 seeds).
    RelKind {
        /// Ownership-tier: this repo owns the counterpart DID.
        Owns = "owns",
        /// Ownership-tier: this repo is owned by the counterpart DID.
        OwnedBy = "ownedBy",
        /// This repo is a member of the counterpart (an account).
        MemberOf = "memberOf",
        /// This repo (an account) has the counterpart as a member.
        HasMember = "hasMember",
        /// This repo consents to something the counterpart does (gallery consent).
        ConsentsTo = "consentsTo",
    }
);

impl RelKind {
    /// The kind the other half must carry for the pair to be defined.
    /// `ConsentsTo` pairs with itself; unknown kinds pair with nothing.
    pub fn pair(&self) -> Option<RelKind> {
        Some(match self {
            Self::Owns => Self::OwnedBy,
            Self::OwnedBy => Self::Owns,
            Self::MemberOf => Self::HasMember,
            Self::HasMember => Self::MemberOf,
            Self::ConsentsTo => Self::ConsentsTo,
            Self::Unknown(_) => return None,
        })
    }

    /// Ownership-tier kinds additionally require key control (verified
    /// against the owned DID's PLC log) — two records alone are not ownership.
    pub fn is_ownership_tier(&self) -> bool {
        matches!(self, Self::Owns | Self::OwnedBy)
    }
}

// ─── the atproto data-model check for opaque values ─────────────────────────

/// Reject what the atproto data model forbids inside a record: floats,
/// `null`, and integers outside ±2⁵³. Applied to `payload` and `scope` on
/// construction so a malformed value can never reach the signer.
fn check_data_model(value: &serde_json::Value, path: &mut String) -> Result<(), CodecError> {
    const MAX_SAFE: u64 = (1 << 53) - 1;
    let fail = |path: &str, detail: &'static str| CodecError::DisallowedValue {
        path: if path.is_empty() {
            "/".into()
        } else {
            path.to_string()
        },
        detail,
    };
    match value {
        serde_json::Value::Null => Err(fail(path, "null is not allowed; omit the field")),
        serde_json::Value::Number(n) => {
            if n.is_f64() {
                Err(fail(path, "floats are not allowed"))
            } else if n.as_u64().is_some_and(|u| u > MAX_SAFE)
                || n.as_i64().is_some_and(|i| i.unsigned_abs() > MAX_SAFE)
            {
                Err(fail(path, "integer exceeds 53 bits"))
            } else {
                Ok(())
            }
        }
        serde_json::Value::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                let len = path.len();
                path.push('/');
                path.push_str(&i.to_string());
                check_data_model(item, path)?;
                path.truncate(len);
            }
            Ok(())
        }
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                let len = path.len();
                path.push('/');
                path.push_str(k);
                check_data_model(v, path)?;
                path.truncate(len);
            }
            Ok(())
        }
        serde_json::Value::Bool(_) | serde_json::Value::String(_) => Ok(()),
    }
}

/// Validate an opaque `payload` / `scope` value against the data model.
pub fn check_opaque(value: &serde_json::Value) -> Result<(), CodecError> {
    check_data_model(value, &mut String::new())
}

// ─── the records ────────────────────────────────────────────────────────────

/// `net.got-paws.acp.claim` — a fact the subject states about themself, in
/// their own repo. Proves nothing by itself; it is what an attestation binds
/// to by content hash. The subject is the repo owner and is not repeated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Claim {
    /// Always [`CLAIM_TYPE`].
    #[serde(rename = "$type")]
    pub type_: ClaimType,
    /// Claim kind from the catalog.
    pub kind: ClaimKind,
    /// Kind-defined content, opaque to the protocol.
    pub payload: serde_json::Value,
    /// When the subject stated it.
    pub created_at: Datetime,
}

impl Claim {
    /// Build a claim, checking `payload` against the data model.
    pub fn new(
        kind: ClaimKind,
        payload: serde_json::Value,
        created_at: Datetime,
    ) -> Result<Self, CodecError> {
        check_opaque(&payload)?;
        Ok(Self {
            type_: ClaimType,
            kind,
            payload,
            created_at,
        })
    }
}

/// Everything in an attestation except the signature — what the attestor
/// fills in before signing, and what the pre-image is built from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnsignedAttestation {
    /// Always [`ATTESTATION_TYPE`].
    #[serde(rename = "$type")]
    pub type_: AttestationType,
    /// The exact claim (address + content CID) being vouched for.
    pub claim: StrongRef,
    /// Who vouches. Resolved to a DID document for the key at verification.
    pub attestor: Did,
    /// Who it is about — for export self-containment; the transplant defense
    /// is the `$sig` binding, **not** this field.
    pub subject: Did,
    /// When the attestor signed.
    pub issued_at: Datetime,
    /// When it stops being in force. Required: stale vouches age out.
    pub expires_at: Datetime,
    /// Where the revocation bit lives; absent = irrevocable until expiry.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<StatusRef>,
    /// The attestor's stated diligence (`email-challenge`, `oauth`, …). Informational.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
}

impl UnsignedAttestation {
    /// Build the unsigned body. `status` and `method` are set on the value
    /// afterwards if wanted.
    pub fn new(
        claim: StrongRef,
        attestor: Did,
        subject: Did,
        issued_at: Datetime,
        expires_at: Datetime,
    ) -> Self {
        Self {
            type_: AttestationType,
            claim,
            attestor,
            subject,
            issued_at,
            expires_at,
            status: None,
            method: None,
        }
    }

    /// Attach a signature, producing the stored record.
    pub fn with_sig(self, sig: Sig) -> Attestation {
        Attestation { body: self, sig }
    }
}

/// `net.got-paws.acp.attestation` — an attestor's signed vouch for one exact
/// claim, stored **in the subject's repo**. The repo commit signature (the
/// subject's) governs custody; the inner [`Sig`] governs truth.
///
/// On the wire this is one flat map: the [`UnsignedAttestation`] fields plus
/// `sig`. The split exists so the pre-image can be built from the body alone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attestation {
    /// Every field but the signature.
    #[serde(flatten)]
    pub body: UnsignedAttestation,
    /// The attestor's signature over the pre-image CID (see [`super::sign`](mod@super::sign)).
    pub sig: Sig,
}

impl Attestation {
    /// The fields the signature covers.
    pub fn unsigned(&self) -> &UnsignedAttestation {
        &self.body
    }
}

/// `net.got-paws.acp.relationship` — one half of a Consensual Claims System
/// pair. Each party writes one in its own repo; the relationship exists iff
/// both halves exist and name each other. No inner signature: the repo commit
/// signature is the assertion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Relationship {
    /// Always [`RELATIONSHIP_TYPE`].
    #[serde(rename = "$type")]
    pub type_: RelationshipType,
    /// This side's kind; the other half must carry [`RelKind::pair`].
    pub relationship: RelKind,
    /// The other party.
    pub counterpart: Did,
    /// The expected address of the other half, once known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub counterpart_record: Option<AtUri>,
    /// Content this side is authoritative for (role, consent terms).
    /// Verifiers ignore scope a side is not authoritative for.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<serde_json::Value>,
    /// When this side asserted it.
    pub created_at: Datetime,
}

impl Relationship {
    /// Build a half, checking `scope` against the data model.
    pub fn new(
        relationship: RelKind,
        counterpart: Did,
        created_at: Datetime,
        scope: Option<serde_json::Value>,
    ) -> Result<Self, CodecError> {
        if let Some(scope) = &scope {
            check_opaque(scope)?;
        }
        Ok(Self {
            type_: RelationshipType,
            relationship,
            counterpart,
            counterpart_record: None,
            scope,
            created_at,
        })
    }
}

#[cfg(test)]
pub(crate) mod fixtures {
    //! Kit's story, as fixed records — shared by the record and sign tests.
    use super::*;

    pub fn kit() -> Did {
        Did::new("did:plc:kit1234567890abcdefghijkl")
    }
    pub fn mallory() -> Did {
        Did::new("did:plc:mallory7890abcdefghijklmn")
    }
    pub fn attestor() -> Did {
        Did::new("did:web:attest.example")
    }
    pub fn claim() -> Claim {
        Claim::new(
            ClaimKind::Email,
            serde_json::json!({ "address": "kit@example.com" }),
            Datetime::parse("2026-08-20T09:00:00Z").unwrap(),
        )
        .unwrap()
    }
    pub fn claim_ref() -> StrongRef {
        let cid = RecordCid::of(&canonical_bytes(&claim()).unwrap());
        StrongRef::new(
            AtUri::parse(&format!(
                "at://{}/{}/3kx2vp5qmek2h",
                kit().as_str(),
                CLAIM_TYPE
            ))
            .unwrap(),
            &cid,
        )
    }
    /// The minimal body: no status, no method.
    pub fn body() -> UnsignedAttestation {
        UnsignedAttestation::new(
            claim_ref(),
            attestor(),
            kit(),
            Datetime::parse("2026-08-20T10:00:00Z").unwrap(),
            Datetime::parse("2026-09-19T10:00:00Z").unwrap(),
        )
    }
    /// The full body: status and method present.
    pub fn body_full() -> UnsignedAttestation {
        let mut b = body();
        b.status = Some(StatusRef {
            list: "https://attest.example/status/1".parse().unwrap(),
            index: 4127,
        });
        b.method = Some("email-challenge".into());
        b
    }
    pub fn relationship() -> Relationship {
        let mut r = Relationship::new(
            RelKind::Owns,
            Did::new("did:plc:fox1234567890abcdefghijkl"),
            Datetime::parse("2026-08-20T11:00:00Z").unwrap(),
            None,
        )
        .unwrap();
        r.counterpart_record = Some(
            AtUri::parse(
                "at://did:plc:fox1234567890abcdefghijkl/net.got-paws.acp.relationship/ab12",
            )
            .unwrap(),
        );
        r
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::*;
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    // ── pinned bytes ────────────────────────────────────────────────────────
    // If any of these change, the wire format changed: every existing
    // signature and strongRef in the world stops resolving. Do not "update"
    // a fixture without a spec change that says why.

    #[test]
    fn keys_come_out_length_first() {
        let bytes = canonical_bytes(&claim()).unwrap();
        // kind(4) < $type(5) < payload(7) < createdAt(9)
        let mut last = 0;
        for k in ["kind", "$type", "payload", "createdAt"] {
            let pos = bytes
                .windows(k.len())
                .position(|w| w == k.as_bytes())
                .unwrap_or_else(|| panic!("key {k} missing"));
            assert!(pos > last, "key {k} out of canonical order");
            last = pos;
        }
    }

    #[test]
    fn pinned_vectors() {
        // THE WIRE FORMAT. Generated by this crate, then cross-checked with an
        // independent encoder (see `vectors` below for the tool + version).
        // A change here breaks every signature and strongRef in the world.
        let cases: [(&str, Vec<u8>); 4] = [
            ("claim", canonical_bytes(&claim()).unwrap()),
            (
                "attestation-min",
                canonical_bytes(&body().with_sig(Sig(vec![0xAB; 64]))).unwrap(),
            ),
            (
                "attestation-full",
                canonical_bytes(&body_full().with_sig(Sig(vec![0xAB; 64]))).unwrap(),
            ),
            ("relationship", canonical_bytes(&relationship()).unwrap()),
        ];
        for (name, bytes) in &cases {
            println!("{name}: {}", hex(bytes));
            println!("{name} cid: {}", RecordCid::of(bytes));
        }
        assert_eq!(hex(&cases[0].1), super::tests::vectors::CLAIM);
        assert_eq!(hex(&cases[1].1), super::tests::vectors::ATTESTATION_MIN);
        assert_eq!(hex(&cases[2].1), super::tests::vectors::ATTESTATION_FULL);
        assert_eq!(hex(&cases[3].1), super::tests::vectors::RELATIONSHIP);
        assert_eq!(
            RecordCid::of(&cases[0].1).to_string(),
            super::tests::vectors::CLAIM_CID
        );
    }

    /// Cross-checked 2026-08-20 against an independent encoder: python
    /// `cbor2` 6.1.4 with `canonical=True` (RFC 8949 §4.2.1 length-first key
    /// order) reproduces every string below byte-for-byte, and the CIDs via
    /// `sha256` + the hand-built CIDv1 prefix. The
    /// inputs are exactly `fixtures::*`.
    pub(super) mod vectors {
        pub const CLAIM: &str = "a4646b696e6465656d61696c652474797065766e65742e676f742d706177732e6163702e636c61696d677061796c6f6164a167616464726573736f6b6974406578616d706c652e636f6d6963726561746564417474323032362d30382d32305430393a30303a30305a";
        pub const CLAIM_CID: &str = "bafyreihuihzqug57iwailciamsvfctyrz76w4bf5mjxsfl4y5seje5ziya";
        pub const ATTESTATION_MIN: &str = "a7637369675840abababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababab652474797065781c6e65742e676f742d706177732e6163702e6174746573746174696f6e65636c61696da263636964783b62616679726569687569687a7175673537697761696c6369616d737666637479727a373677346266356d6a7873666c34793573656a65357a69796163757269784b61743a2f2f6469643a706c633a6b6974313233343536373839306162636465666768696a6b6c2f6e65742e676f742d706177732e6163702e636c61696d2f336b7832767035716d656b3268677375626a65637478216469643a706c633a6b6974313233343536373839306162636465666768696a6b6c686174746573746f72766469643a7765623a6174746573742e6578616d706c6568697373756564417474323032362d30382d32305431303a30303a30305a6965787069726573417474323032362d30392d31395431303a30303a30305a";
        pub const ATTESTATION_FULL: &str = "a9637369675840abababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababab652474797065781c6e65742e676f742d706177732e6163702e6174746573746174696f6e65636c61696da263636964783b62616679726569687569687a7175673537697761696c6369616d737666637479727a373677346266356d6a7873666c34793573656a65357a69796163757269784b61743a2f2f6469643a706c633a6b6974313233343536373839306162636465666768696a6b6c2f6e65742e676f742d706177732e6163702e636c61696d2f336b7832767035716d656b3268666d6574686f646f656d61696c2d6368616c6c656e676566737461747573a2646c697374781f68747470733a2f2f6174746573742e6578616d706c652f7374617475732f3165696e64657819101f677375626a65637478216469643a706c633a6b6974313233343536373839306162636465666768696a6b6c686174746573746f72766469643a7765623a6174746573742e6578616d706c6568697373756564417474323032362d30382d32305431303a30303a30305a6965787069726573417474323032362d30392d31395431303a30303a30305a";
        pub const RELATIONSHIP: &str = "a5652474797065781d6e65742e676f742d706177732e6163702e72656c6174696f6e736869706963726561746564417474323032362d30382d32305431313a30303a30305a6b636f756e7465727061727478216469643a706c633a666f78313233343536373839306162636465666768696a6b6c6c72656c6174696f6e73686970646f776e7371636f756e746572706172745265636f7264784961743a2f2f6469643a706c633a666f78313233343536373839306162636465666768696a6b6c2f6e65742e676f742d706177732e6163702e72656c6174696f6e736869702f61623132";
    }

    // ── structural guarantees ───────────────────────────────────────────────

    #[test]
    fn keys_sorted_canonically_regardless_of_struct_order() {
        #[derive(Serialize)]
        struct Scrambled {
            zz: u8,
            a: u8,
            bbb: u8,
            cc: u8,
        }
        let bytes = canonical_bytes(&Scrambled {
            zz: 1,
            a: 2,
            bbb: 3,
            cc: 4,
        })
        .unwrap();
        // a4 | 61 61 02 | 62 63 63 04 | 62 7a 7a 01 | 63 62 62 62 03
        assert_eq!(hex(&bytes), "a461610262636304627a7a016362626203");
    }

    #[test]
    fn sig_is_a_cbor_byte_string() {
        let bytes = canonical_bytes(&body().with_sig(Sig(vec![0x11; 64]))).unwrap();
        let pos = bytes.windows(3).position(|w| w == b"sig").unwrap();
        // after the 3-byte key: 0x58 (bytes, 1-byte length) 0x40 (64)
        assert_eq!(&bytes[pos + 3..pos + 5], &[0x58, 0x40]);
    }

    #[test]
    fn optional_fields_are_absent_not_null() {
        let min = canonical_bytes(&body()).unwrap();
        assert!(!min.windows(6).any(|w| w == b"status"));
        assert!(!min.windows(6).any(|w| w == b"method"));
        assert!(!min.contains(&0xf6), "no CBOR null anywhere");
        let full = canonical_bytes(&body_full()).unwrap();
        assert!(full.windows(6).any(|w| w == b"status"));
        assert!(full.len() > min.len());
    }

    #[test]
    fn strongref_cid_is_text_not_link() {
        let bytes = canonical_bytes(&claim_ref()).unwrap();
        assert!(!bytes.windows(2).any(|w| w == [0xd8, 0x2a]), "no tag 42");
        let pos = bytes.windows(3).position(|w| w == b"cid").unwrap();
        assert_eq!(
            bytes[pos + 3] & 0xe0,
            0x60,
            "cid value is major type 3 (text)"
        );
    }

    #[test]
    fn record_cid_matches_plc_cid() {
        let bytes = canonical_bytes(&claim()).unwrap();
        assert_eq!(RecordCid::of(&bytes).to_string(), crate::plc::cid(&bytes));
        assert!(RecordCid::of(&bytes).to_string().starts_with("bafyrei"));
    }

    #[test]
    fn record_cid_round_trips_as_text() {
        let cid = RecordCid::of(b"x");
        let text = cid.to_string();
        assert_eq!(text.parse::<RecordCid>().unwrap(), cid);
        assert_eq!(RecordCid::try_from(text.as_str()).unwrap(), cid);
        for bad in [
            "",
            "z",
            "bafyrei",
            "Bafyreihuihzqug57iwailciamsvfctyrz76w4bf5mjxsfl4y5seje5ziya",
        ] {
            assert!(RecordCid::parse(bad).is_err(), "{bad}");
        }
        // A CIDv1 with a different codec prefix is not a record CID.
        let mut raw = *cid.as_bytes();
        raw[1] = 0x55; // raw codec
        let other = format!(
            "b{}",
            data_encoding::BASE32_NOPAD.encode(&raw).to_lowercase()
        );
        assert!(RecordCid::parse(&other).is_err());
        // Datetime and AtUri speak the same std vocabulary.
        assert!("2026-08-20T09:00:00Z".parse::<Datetime>().is_ok());
        assert!(AtUri::try_from("at://did:plc:abc/c/r".to_string()).is_ok());
    }

    #[test]
    fn round_trips() {
        let a = body_full().with_sig(Sig(vec![7; 64]));
        let bytes = canonical_bytes(&a).unwrap();
        let back: Attestation = from_canonical_bytes(&bytes).unwrap();
        assert_eq!(back, a);
        assert_eq!(canonical_bytes(&back).unwrap(), bytes);

        let c = claim();
        let back: Claim = from_canonical_bytes(&canonical_bytes(&c).unwrap()).unwrap();
        assert_eq!(back, c);

        let r = relationship();
        let back: Relationship = from_canonical_bytes(&canonical_bytes(&r).unwrap()).unwrap();
        assert_eq!(back, r);
    }

    #[test]
    fn unknown_kind_round_trips() {
        let mut c = claim();
        c.kind = ClaimKind::from("phone");
        let back: Claim = from_canonical_bytes(&canonical_bytes(&c).unwrap()).unwrap();
        assert_eq!(back.kind, ClaimKind::Unknown("phone".into()));
        assert_eq!(RelKind::from("sponsors").pair(), None);
        assert_eq!(RelKind::Owns.pair(), Some(RelKind::OwnedBy));
        assert_eq!(RelKind::ConsentsTo.pair(), Some(RelKind::ConsentsTo));
        assert!(RelKind::OwnedBy.is_ownership_tier());
        assert!(!RelKind::MemberOf.is_ownership_tier());
    }

    #[test]
    fn wrong_type_marker_is_rejected() {
        let mut bytes = canonical_bytes(&claim()).unwrap();
        // Rewrite the NSID's last byte: "…claim" → "…claiM".
        let pos = bytes.windows(5).position(|w| w == b"claim").unwrap();
        bytes[pos + 4] = b'M';
        let err = from_canonical_bytes::<Claim>(&bytes).unwrap_err();
        assert!(matches!(err, CodecError::Decode(_)));
        // And an attestation's bytes do not decode as a claim.
        let att = canonical_bytes(&body().with_sig(Sig(vec![0; 64]))).unwrap();
        assert!(from_canonical_bytes::<Claim>(&att).is_err());
    }

    #[test]
    fn payload_rejects_float_null_and_wide_ints() {
        let at = |v: serde_json::Value| {
            Claim::new(
                ClaimKind::Email,
                v,
                Datetime::parse("2026-01-01T00:00:00Z").unwrap(),
            )
        };
        assert!(at(serde_json::json!({ "x": 1.5 })).is_err());
        assert!(at(serde_json::json!({ "x": null })).is_err());
        assert!(at(serde_json::json!({ "x": [1, { "y": 9007199254740992u64 }] })).is_err());
        assert!(at(serde_json::json!({ "x": [1, { "y": 9007199254740991u64 }] })).is_ok());
        assert!(at(serde_json::json!({ "x": -9007199254740991i64 })).is_ok());
        match at(serde_json::json!({ "a": { "b": [true, 2.0] } })).unwrap_err() {
            CodecError::DisallowedValue { path, .. } => assert_eq!(path, "/a/b/1"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn payload_key_order_does_not_change_bytes() {
        // serde_json may preserve insertion order (F35); the encoder must not.
        let a = serde_json::json!({ "zeta": 1, "alpha": 2 });
        let b = serde_json::json!({ "alpha": 2, "zeta": 1 });
        let dt = Datetime::parse("2026-01-01T00:00:00Z").unwrap();
        assert_eq!(
            canonical_bytes(&Claim::new(ClaimKind::Email, a, dt.clone()).unwrap()).unwrap(),
            canonical_bytes(&Claim::new(ClaimKind::Email, b, dt).unwrap()).unwrap()
        );
    }

    #[test]
    fn datetime_syntax() {
        for ok in [
            "2026-08-20T09:00:00Z",
            "2026-08-20T09:00:00.123Z",
            "2026-08-20T09:00:00+02:00",
            "2026-08-20t09:00:00.5-05:30",
        ] {
            Datetime::parse(ok).unwrap_or_else(|e| panic!("{ok}: {e}"));
        }
        for bad in [
            "",
            "2026-08-20",
            "2026-08-20T09:00Z",
            "2026-08-20T09:00:00",
            "2026-08-20T09:00:00.Z",
            "2026-08-20T09:00:00+0200",
            "2026-08-20 09:00:00Z",
            "2026-08-20T09:00:00Zx",
        ] {
            assert!(Datetime::parse(bad).is_err(), "{bad} accepted");
        }
    }

    #[test]
    fn datetime_ranges() {
        for ok in [
            "2024-02-29T00:00:00Z",
            "2000-02-29T00:00:00Z",
            "2026-12-31T23:59:60Z",
            "2026-01-01T00:00:00+23:59",
        ] {
            Datetime::parse(ok).unwrap_or_else(|e| panic!("{ok}: {e}"));
        }
        for bad in [
            "2026-13-45T25:00:00Z",
            "2026-00-10T00:00:00Z",
            "2026-02-29T00:00:00Z",
            "1900-02-29T00:00:00Z",
            "2026-04-31T00:00:00Z",
            "2026-08-00T00:00:00Z",
            "2026-08-20T24:00:00Z",
            "2026-08-20T09:60:00Z",
            "2026-08-20T09:00:61Z",
            "2026-08-20T09:00:00+24:00",
            "2026-08-20T09:00:00-05:60",
        ] {
            assert!(Datetime::parse(bad).is_err(), "{bad} accepted");
        }
    }

    #[test]
    fn datetime_to_unix() {
        let u = |s: &str| Datetime::parse(s).unwrap().to_unix();
        assert_eq!(u("1970-01-01T00:00:00Z"), 0);
        assert_eq!(u("2000-03-01T00:00:00Z"), 951_868_800); // day after a leap day
        assert_eq!(u("2024-02-29T12:00:00Z"), 1_709_208_000);
        assert_eq!(u("2026-08-20T10:00:00Z"), 1_787_220_000);
        assert_eq!(u("2026-08-20T12:00:00+02:00"), u("2026-08-20T10:00:00Z"));
        assert_eq!(u("2026-08-20T04:30:00-05:30"), u("2026-08-20T10:00:00Z"));
        assert_eq!(u("2026-08-20T10:00:00.999Z"), u("2026-08-20T10:00:00Z"));
        assert!(u("2026-09-19T10:00:00Z") > u("2026-08-20T10:00:00Z"));
        // Full precision keeps the fraction; digits past nine are dropped.
        let n = |s: &str| Datetime::parse(s).unwrap().to_unix_nanos();
        assert_eq!(n("2026-08-20T10:00:00Z"), 1_787_220_000 * 1_000_000_000);
        assert_eq!(
            n("2026-08-20T10:00:00.5Z"),
            n("2026-08-20T10:00:00Z") + 500_000_000
        );
        assert_eq!(
            n("2026-08-20T10:00:00.000000001Z"),
            n("2026-08-20T10:00:00Z") + 1
        );
        assert_eq!(
            n("2026-08-20T10:00:00.0000000019Z"),
            n("2026-08-20T10:00:00Z") + 1
        );
        assert!(n("2026-08-20T10:00:00.900Z") > n("2026-08-20T10:00:00.100Z"));
        assert_eq!(
            n("2026-08-20T12:00:00.25+02:00"),
            n("2026-08-20T10:00:00.25Z")
        );
    }

    #[test]
    fn at_uri_parts() {
        let u = AtUri::parse("at://did:plc:abc/net.got-paws.acp.claim/3k").unwrap();
        assert_eq!(u.authority(), "did:plc:abc");
        assert_eq!(u.collection(), Some("net.got-paws.acp.claim"));
        assert_eq!(u.rkey(), Some("3k"));
        let bare = AtUri::parse("at://kit.example").unwrap();
        assert_eq!(bare.authority(), "kit.example");
        assert_eq!(bare.collection(), None);
        assert_eq!(bare.rkey(), None);
        assert_eq!(
            AtUri::record(&Did::new("did:plc:abc"), "c", "r").as_str(),
            "at://did:plc:abc/c/r"
        );
    }

    #[test]
    fn at_uri_syntax() {
        AtUri::parse("at://did:plc:abc/net.got-paws.acp.claim/3k").unwrap();
        AtUri::parse("at://kit.example").unwrap();
        for bad in ["", "https://x", "at://", "at:///c/r", "at://did:plc:a b/c"] {
            assert!(AtUri::parse(bad).is_err(), "{bad} accepted");
        }
    }

    #[test]
    fn status_uri_rejects_what_a_verifier_must_not_fetch() {
        for ok in [
            "https://attest.example/status/1",
            "https://attest.example:8443/status/1?x=1#f",
            "https://a-b.example",
        ] {
            StatusUri::parse(ok).unwrap_or_else(|e| panic!("{ok}: {e}"));
        }
        for bad in [
            "",
            "http://attest.example/status/1",
            "https://169.254.169.254/latest/meta-data/",
            "https://127.0.0.1/",
            "https://10.0.0.5:5432/",
            "https://[::1]/",
            "https://[fe80::1]:80/",
            "https://localhost/status",
            "https://LOCALHOST:8443/status",
            "https://pds.localhost/status",
            "https://user:pw@attest.example/",
            "https:///status",
            "https://attest.example/st atus",
            "https://attest_example/",
            "ftp://attest.example/",
        ] {
            assert!(StatusUri::parse(bad).is_err(), "{bad} accepted");
        }
        // And the same rule applies on decode.
        let mut b = body_full();
        b.status.as_mut().unwrap().index = 0;
        let bytes = canonical_bytes(&b).unwrap();
        let pos = bytes.windows(8).position(|w| w == b"https://").unwrap();
        let mut evil = bytes.clone();
        evil[pos..pos + 8].copy_from_slice(b"http://1");
        assert!(from_canonical_bytes::<UnsignedAttestation>(&evil).is_err());
        from_canonical_bytes::<UnsignedAttestation>(&bytes).unwrap();
    }

    #[test]
    fn did_in_record_is_validated_on_decode() {
        let mut bytes = canonical_bytes(&relationship()).unwrap();
        let pos = bytes.windows(8).position(|w| w == b"did:plc:").unwrap();
        bytes[pos..pos + 8].copy_from_slice(b"nid:plc:");
        assert!(from_canonical_bytes::<Relationship>(&bytes).is_err());
    }
}
