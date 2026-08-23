//! Claim kinds — five-segment NSIDs, typed per segment.
//!
//! A `kind` reads general → specific, `<tld>.<domain>.acp.<category>.<name>`
//! (`docs/acp.md` §Claim kinds; FORKS F45): the first two segments are the
//! authority that owns the meaning, the third names the protocol, the fourth
//! is ACP's closed category list, the fifth is the kind itself. Each segment
//! is an enum with the values this build knows **and an `Other(String)`**,
//! so a kind minted by anyone else parses, round-trips byte-for-byte, and can
//! be built dynamically. Only *syntax* can fail here (wrong segment count, a
//! bad label); a *value* never does — the spec's "unrecognised kinds are
//! ignored, never rejected".
//!
//! Meaning lives in the spec and the kind's own definition record, not
//! here: `Category::Relationship` says nothing in code about who attests.

use std::fmt;
use std::str::FromStr;

use serde::de::{self, Deserializer};
use serde::{Deserialize, Serialize};

use crate::handle::LABEL_MAX_LEN;

use super::error::CodecError;

/// The longest NSID the atproto spec allows, in characters.
pub const NSID_MAX_LEN: usize = 317;

/// Number of segments in a claim kind.
const SEGMENTS: usize = 5;

// ─── one macro for the four segment enums ───────────────────────────────────

/// A closed set of wire strings plus `Other(String)` for everything else.
///
/// `From<&str>` never fails (an unknown word becomes `Other`), `Display`
/// renders the wire string, and `as_str` is the only hand-rolled accessor.
macro_rules! string_enum {
    ($(#[$doc:meta])* $name:ident { $($(#[$vdoc:meta])* $variant:ident = $s:expr),+ $(,)? }) => {
        $(#[$doc])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        pub enum $name {
            $($(#[$vdoc])* $variant,)+
            /// A value this build does not know. Carried verbatim, rendered
            /// verbatim; never a reason to reject a record.
            Other(String),
        }

        impl $name {
            /// The wire string.
            pub fn as_str(&self) -> &str {
                match self {
                    $(Self::$variant => $s,)+
                    Self::Other(s) => s,
                }
            }
        }

        impl From<&str> for $name {
            fn from(s: &str) -> Self {
                match s {
                    $($s => Self::$variant,)+
                    other => Self::Other(other.to_string()),
                }
            }
        }

        impl ::std::fmt::Display for $name {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                f.write_str(self.as_str())
            }
        }
    };
}

string_enum!(
    /// Segments 1–2: the reversed domain that owns the kind's meaning.
    Authority {
        /// `net.got-paws` — this spec's own kinds.
        GotPaws = "net.got-paws",
        /// `app.zurfur` — Zurfur's kinds; not this spec's.
        Zurfur = "app.zurfur",
    }
);

string_enum!(
    /// Segment 3: the protocol the kind belongs to.
    Protocol {
        /// `acp` — every ACP kind, under any authority.
        Acp = "acp",
    }
);

string_enum!(
    /// Segment 4: ACP's closed category list — what every authority agrees
    /// on. What a category *means* (who claims, who attests, what the
    /// payload carries) is `docs/acp.md` §Claim kinds, not this enum.
    Category {
        /// A fact about the subject.
        Identity = "identity",
        /// The subject and another DID.
        Relationship = "relationship",
    }
);

string_enum!(
    /// Segment 5: the kind itself, camelCase, defined by its authority.
    Name {
        /// Control of an email address.
        Email = "email",
        /// An account on another service.
        ExternalAccount = "externalAccount",
        /// Owner / owned.
        Ownership = "ownership",
        /// Member / account.
        Membership = "membership",
        /// "This DID is a character" — Zurfur's.
        Character = "character",
    }
);

// ─── the kind ───────────────────────────────────────────────────────────────

/// A claim kind: `<tld>.<domain>.<protocol>.<category>.<name>`.
///
/// Built from typed segments ([`ClaimKind::new`]) or parsed from the wire
/// ([`FromStr`], [`TryFrom`], `Deserialize` — one parser). Rendered by
/// [`fmt::Display`] — the one place the segments become a string; `Serialize`
/// goes through it. The seeds are consts: [`ClaimKind::EMAIL`] and friends.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ClaimKind {
    authority: Authority,
    protocol: Protocol,
    category: Category,
    name: Name,
}

impl ClaimKind {
    /// `net.got-paws.acp.identity.email`
    pub const EMAIL: Self = Self::new(
        Authority::GotPaws,
        Protocol::Acp,
        Category::Identity,
        Name::Email,
    );
    /// `net.got-paws.acp.identity.externalAccount`
    pub const EXTERNAL_ACCOUNT: Self = Self::new(
        Authority::GotPaws,
        Protocol::Acp,
        Category::Identity,
        Name::ExternalAccount,
    );
    /// `net.got-paws.acp.relationship.ownership`
    pub const OWNERSHIP: Self = Self::new(
        Authority::GotPaws,
        Protocol::Acp,
        Category::Relationship,
        Name::Ownership,
    );
    /// `net.got-paws.acp.relationship.membership`
    pub const MEMBERSHIP: Self = Self::new(
        Authority::GotPaws,
        Protocol::Acp,
        Category::Relationship,
        Name::Membership,
    );
    /// `app.zurfur.acp.identity.character` — Zurfur's kind, not this spec's.
    pub const CHARACTER: Self = Self::new(
        Authority::Zurfur,
        Protocol::Acp,
        Category::Identity,
        Name::Character,
    );

    /// Assemble a kind from typed segments. Infallible: the known variants
    /// always render a valid NSID. An `Other` carrying bad syntax renders a
    /// string the parser would refuse — build those through
    /// [`FromStr`] instead, which checks.
    pub const fn new(
        authority: Authority,
        protocol: Protocol,
        category: Category,
        name: Name,
    ) -> Self {
        Self {
            authority,
            protocol,
            category,
            name,
        }
    }

    /// Parse the wire form; the same parser as [`FromStr`].
    pub fn parse(raw: &str) -> Result<Self, CodecError> {
        raw.parse()
    }

    /// Segments 1–2.
    pub fn authority(&self) -> &Authority {
        &self.authority
    }

    /// Segment 3.
    pub fn protocol(&self) -> &Protocol {
        &self.protocol
    }

    /// Segment 4.
    pub fn category(&self) -> &Category {
        &self.category
    }

    /// Segment 5.
    pub fn name(&self) -> &Name {
        &self.name
    }

    /// Whether segment 3 is `acp` — i.e. the spec's rules for categories
    /// apply at all.
    pub fn is_acp(&self) -> bool {
        self.protocol == Protocol::Acp
    }
}

fn invalid(detail: impl Into<String>) -> CodecError {
    CodecError::InvalidField {
        field: "kind",
        detail: detail.into(),
    }
}

/// An NSID authority label: lowercase ASCII letters, digits and hyphens, no
/// hyphen at either edge, 1..=[`LABEL_MAX_LEN`] characters.
fn check_label(label: &str, position: usize) -> Result<(), CodecError> {
    if label.is_empty() {
        return Err(invalid(format!("segment {position} is empty")));
    }
    if label.len() > LABEL_MAX_LEN {
        return Err(invalid(format!(
            "segment {position} is {} chars; the max is {LABEL_MAX_LEN}",
            label.len()
        )));
    }
    if label.starts_with('-') || label.ends_with('-') {
        return Err(invalid(format!(
            "segment {position} starts or ends with a hyphen"
        )));
    }
    if let Some(bad) = label
        .chars()
        .find(|&c| !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'))
    {
        return Err(invalid(format!(
            "segment {position} contains {bad:?}; lowercase letters, digits and hyphens only"
        )));
    }
    Ok(())
}

/// An NSID name segment: ASCII letters and digits, first character a
/// letter, 1..=[`LABEL_MAX_LEN`] characters.
fn check_name(name: &str) -> Result<(), CodecError> {
    if name.is_empty() {
        return Err(invalid("name segment is empty"));
    }
    if name.len() > LABEL_MAX_LEN {
        return Err(invalid(format!(
            "name segment is {} chars; the max is {LABEL_MAX_LEN}",
            name.len()
        )));
    }
    if !name.starts_with(|c: char| c.is_ascii_alphabetic()) {
        return Err(invalid("name segment must start with a letter"));
    }
    if let Some(bad) = name.chars().find(|c| !c.is_ascii_alphanumeric()) {
        return Err(invalid(format!(
            "name segment contains {bad:?}; ASCII letters and digits only"
        )));
    }
    Ok(())
}

impl FromStr for ClaimKind {
    type Err = CodecError;

    /// Exactly five dot-separated segments; syntax only. Every segment's
    /// *value* is accepted — unknown ones land in `Other`.
    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        if raw.len() > NSID_MAX_LEN {
            return Err(invalid(format!(
                "{} chars; an NSID is at most {NSID_MAX_LEN}",
                raw.len()
            )));
        }
        let segments: Vec<&str> = raw.split('.').collect();
        if segments.len() != SEGMENTS {
            return Err(invalid(format!(
                "expected {SEGMENTS} segments (tld.domain.protocol.category.name), found {}",
                segments.len()
            )));
        }
        for (i, label) in segments[..SEGMENTS - 1].iter().enumerate() {
            check_label(label, i + 1)?;
        }
        check_name(segments[SEGMENTS - 1])?;
        let authority = format!("{}.{}", segments[0], segments[1]);
        Ok(Self {
            authority: Authority::from(authority.as_str()),
            protocol: Protocol::from(segments[2]),
            category: Category::from(segments[3]),
            name: Name::from(segments[4]),
        })
    }
}

impl TryFrom<&str> for ClaimKind {
    type Error = CodecError;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl TryFrom<String> for ClaimKind {
    type Error = CodecError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl fmt::Display for ClaimKind {
    /// The five segments, dot-joined — the wire form.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}.{}.{}.{}",
            self.authority, self.protocol, self.category, self.name
        )
    }
}

impl fmt::Debug for ClaimKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ClaimKind({self})")
    }
}

impl Serialize for ClaimKind {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for ClaimKind {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        String::deserialize(d)?.parse().map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEEDS: [(&ClaimKind, &str); 5] = [
        (&ClaimKind::EMAIL, "net.got-paws.acp.identity.email"),
        (
            &ClaimKind::EXTERNAL_ACCOUNT,
            "net.got-paws.acp.identity.externalAccount",
        ),
        (
            &ClaimKind::OWNERSHIP,
            "net.got-paws.acp.relationship.ownership",
        ),
        (
            &ClaimKind::MEMBERSHIP,
            "net.got-paws.acp.relationship.membership",
        ),
        (&ClaimKind::CHARACTER, "app.zurfur.acp.identity.character"),
    ];

    #[test]
    fn seeds_render_and_parse_to_themselves() {
        for (kind, wire) in SEEDS {
            assert_eq!(kind.to_string(), wire);
            assert_eq!(&ClaimKind::parse(wire).unwrap(), kind, "{wire}");
            assert_eq!(&wire.parse::<ClaimKind>().unwrap(), kind);
            assert_eq!(&ClaimKind::try_from(wire).unwrap(), kind);
            assert_eq!(&ClaimKind::try_from(wire.to_string()).unwrap(), kind);
            assert!(kind.is_acp());
            // No `Other` anywhere in a seed.
            assert!(!matches!(kind.authority(), Authority::Other(_)));
            assert!(!matches!(kind.category(), Category::Other(_)));
            assert!(!matches!(kind.name(), Name::Other(_)));
        }
        assert_eq!(ClaimKind::EMAIL.category(), &Category::Identity);
        assert_eq!(ClaimKind::OWNERSHIP.category(), &Category::Relationship);
        assert_eq!(ClaimKind::CHARACTER.authority(), &Authority::Zurfur);
        assert_eq!(
            format!("{:?}", ClaimKind::EMAIL),
            "ClaimKind(net.got-paws.acp.identity.email)"
        );
    }

    #[test]
    fn seeds_round_trip_through_dag_cbor() {
        for (kind, wire) in SEEDS {
            let bytes = serde_ipld_dagcbor::to_vec(kind).unwrap();
            // A text string of the wire form, nothing else.
            assert_eq!(bytes[0], 0x78, "one-byte-length text string");
            assert_eq!(&bytes[2..], wire.as_bytes());
            let back: ClaimKind = serde_ipld_dagcbor::from_slice(&bytes).unwrap();
            assert_eq!(&back, kind);
        }
    }

    #[test]
    fn other_on_every_segment_round_trips_verbatim() {
        type Check = fn(&ClaimKind) -> bool;
        let cases: [(&str, Check); 5] = [
            ("com.example.acp.identity.foo", |k: &ClaimKind| {
                matches!(k.authority(), Authority::Other(a) if a == "com.example")
                    && k.is_acp()
                    && k.category() == &Category::Identity
                    && matches!(k.name(), Name::Other(n) if n == "foo")
            }),
            ("net.got-paws.acp.consent.artwork", |k: &ClaimKind| {
                k.authority() == &Authority::GotPaws
                    && matches!(k.category(), Category::Other(c) if c == "consent")
            }),
            ("net.got-paws.xyz.identity.email", |k: &ClaimKind| {
                !k.is_acp()
                    && matches!(k.protocol(), Protocol::Other(p) if p == "xyz")
                    && k.name() == &Name::Email
            }),
            (
                "net.got-paws.acp.identity.newThing",
                |k: &ClaimKind| matches!(k.name(), Name::Other(n) if n == "newThing"),
            ),
            ("com.example.foo.bar.baz", |k: &ClaimKind| {
                matches!(k.authority(), Authority::Other(_))
                    && matches!(k.protocol(), Protocol::Other(_))
                    && matches!(k.category(), Category::Other(_))
                    && matches!(k.name(), Name::Other(_))
            }),
        ];
        for (wire, check) in cases {
            let kind = ClaimKind::parse(wire).unwrap_or_else(|e| panic!("{wire}: {e}"));
            assert!(check(&kind), "{wire}");
            assert_eq!(kind.to_string(), wire);
            let bytes = serde_ipld_dagcbor::to_vec(&kind).unwrap();
            let back: ClaimKind = serde_ipld_dagcbor::from_slice(&bytes).unwrap();
            assert_eq!(back, kind);
        }
        // Dynamic construction renders the same wire form.
        let dynamic = ClaimKind::new(
            Authority::Other("com.example".into()),
            Protocol::Acp,
            Category::Identity,
            Name::Other("foo".into()),
        );
        assert_eq!(dynamic.to_string(), "com.example.acp.identity.foo");
        assert_eq!(ClaimKind::parse(&dynamic.to_string()).unwrap(), dynamic);
    }

    #[test]
    fn segment_enums_speak_the_wire() {
        assert_eq!(Authority::from("net.got-paws"), Authority::GotPaws);
        assert_eq!(Authority::from("org.other").as_str(), "org.other");
        assert_eq!(Protocol::from("acp"), Protocol::Acp);
        assert_eq!(Category::from("relationship").to_string(), "relationship");
        assert_eq!(Name::from("externalAccount"), Name::ExternalAccount);
        assert_eq!(
            Name::from("external-account"),
            Name::Other("external-account".into())
        );
    }

    #[test]
    fn syntax_is_checked_values_are_not() {
        let long_label = "a".repeat(LABEL_MAX_LEN + 1);
        let too_long_total = format!("net.got-paws.acp.identity.{}", "a".repeat(300));
        let bad: Vec<(String, &str)> = vec![
            ("".into(), "empty"),
            ("net.got-paws.acp.identity".into(), "four segments"),
            (
                "net.got-paws.acp.identity.email.extra".into(),
                "six segments",
            ),
            ("net..acp.identity.email".into(), "empty segment"),
            ("net.got-paws.acp.identity.".into(), "empty name"),
            (
                "net.Got-Paws.acp.identity.email".into(),
                "uppercase in authority",
            ),
            ("net.got_paws.acp.identity.email".into(), "underscore"),
            ("net.got paws.acp.identity.email".into(), "space"),
            (
                format!("net.{long_label}.acp.identity.email"),
                "label too long",
            ),
            (
                "net.got-paws.acp.identity.1email".into(),
                "name starts with a digit",
            ),
            ("net.got-paws.acp.identity.e-mail".into(), "hyphen in name"),
            ("net.-got-paws.acp.identity.email".into(), "leading hyphen"),
            ("net.got-paws-.acp.identity.email".into(), "trailing hyphen"),
            (too_long_total, "over 317 chars"),
            ("email".into(), "the pre-F45 bare word"),
        ];
        for (raw, why) in bad {
            let err = ClaimKind::parse(&raw).expect_err(why);
            assert!(
                matches!(err, CodecError::InvalidField { field: "kind", .. }),
                "{why}: {err}"
            );
        }
        // And the same parser guards decode.
        let bytes = serde_ipld_dagcbor::to_vec("net.got-paws.acp").unwrap();
        assert!(serde_ipld_dagcbor::from_slice::<ClaimKind>(&bytes).is_err());
    }
}
