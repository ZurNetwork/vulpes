//! Claim kinds — five-segment NSIDs, typed per segment.
//!
//! A `kind` reads general → specific, `<tld>.<domain>.acp.<category>.<name>`
//! (`docs/acp.md` §Claim kinds; FORKS F45): the first two segments are the
//! authority that owns the meaning, the third names the protocol, the fourth
//! is ACP's closed category list, the fifth is the kind itself. Each segment
//! is an enum with the values this build knows **and an `Other`** holding the
//! syntax-checked segment, so a kind minted by anyone else parses, round-trips
//! byte-for-byte, and can be built dynamically. Only *syntax* can fail here
//! (wrong segment count, a bad label), and only at the newtype doors
//! ([`ClaimAuthority`], [`ClaimLabel`], [`ClaimName`]); a *value* never does —
//! the spec's "unrecognised kinds are ignored, never rejected".
//!
//! Meaning lives in the spec and the kind's own definition record, not
//! here: `Category::Relationship` says nothing in code about who attests.

use std::fmt::{self, Display};
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

/// A closed set of wire strings plus `Other` holding the checked segment.
///
/// `$checked` is the segment's syntax-checked newtype ([`ClaimAuthority`],
/// [`ClaimLabel`] or [`ClaimName`]); `From<$checked>` is the **only**
/// constructor besides the known variants, so an `Other` can never carry a
/// value the parser would refuse. An unknown word becomes `Other`, never an
/// error; `Display` renders the wire string.
macro_rules! string_enum {
    ($(#[$doc:meta])* $name:ident : $checked:ty { $($(#[$vdoc:meta])* $variant:ident = $s:expr),+ $(,)? }) => {
        $(#[$doc])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        pub enum $name {
            $($(#[$vdoc])* $variant,)+
            /// A value this build does not know. Syntax-checked, carried
            /// verbatim, rendered verbatim; never a reason to reject a record.
            Other($checked),
        }

        impl $name {
            /// The wire string.
            pub fn as_str(&self) -> &str {
                match self {
                    $(Self::$variant => $s,)+
                    Self::Other(checked) => checked.as_str(),
                }
            }
        }

        impl From<$checked> for $name {
            /// A known word becomes its variant; anything else is `Other`,
            /// moved in as-is.
            fn from(checked: $checked) -> Self {
                match checked.as_str() {
                    $($s => Self::$variant,)+
                    _ => Self::Other(checked),
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
    Authority: ClaimAuthority {
        /// `net.got-paws` — this spec's own kinds.
        GotPaws = "net.got-paws",
        /// `app.zurfur` — Zurfur's kinds; not this spec's.
        Zurfur = "app.zurfur",
    }
);

string_enum!(
    /// Segment 3: the protocol the kind belongs to.
    Protocol: ClaimLabel {
        /// `acp` — every ACP kind, under any authority.
        Acp = "acp",
    }
);

string_enum!(
    /// Segment 4: ACP's closed category list — what every authority agrees
    /// on. What a category *means* (who claims, who attests, what the
    /// payload carries) is `docs/acp.md` §Claim kinds, not this enum.
    Category: ClaimLabel {
        /// A fact about the subject.
        Identity = "identity",
        /// The subject and another DID.
        Relationship = "relationship",
    }
);

string_enum!(
    /// Segment 5: the kind itself, camelCase, defined by its authority.
    Name: ClaimName {
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
/// ([`FromStr`], `Deserialize` — one parser). Rendered by
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

    /// Assemble a kind from typed segments. Infallible, and the result always
    /// renders an NSID the parser accepts: the known variants are valid by
    /// construction and an `Other` can only hold a segment that already
    /// passed its newtype's syntax check.
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

/// A `kind` syntax error: [`CodecError::InvalidField`] on field `"kind"`.
fn invalid(detail: impl Into<String>) -> CodecError {
    CodecError::InvalidField {
        field: "kind",
        detail: detail.into(),
    }
}

/// One checked label of segments 1–4: non-empty, at most [`LABEL_MAX_LEN`]
/// chars, lowercase ASCII letters, digits and interior hyphens only — the
/// atproto NSID domain-authority rules.
///
/// It is the door into [`Protocol`] and [`Category`]: `From<ClaimLabel>`
/// turns a checked label into its variant, or into `Other` when this build
/// does not know the word. Built through [`FromStr`], which is where the
/// syntax is judged; the value never is.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ClaimLabel(String);

impl ClaimLabel {
    /// The label verbatim.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Display for ClaimLabel {
    /// The label verbatim — what was checked is what is rendered.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl FromStr for ClaimLabel {
    type Err = CodecError;

    /// Check one label's syntax. Fails only on shape — length, case, an
    /// illegal character, a leading or trailing hyphen.
    fn from_str(label: &str) -> Result<Self, Self::Err> {
        if label.is_empty() {
            return Err(invalid("Segment is empty"));
        }
        if label.len() > LABEL_MAX_LEN {
            return Err(invalid(format!(
                "segment is {} chars; the max is {LABEL_MAX_LEN}",
                label.len()
            )));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(invalid("segment starts or ends with a hyphen"));
        }
        if let Some(bad) = label
            .chars()
            .find(|&c| !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'))
        {
            return Err(invalid(format!(
                "segment contains {bad:?}; lowercase letters, digits and hyphens only"
            )));
        }

        Ok(Self(label.into()))
    }
}

/// The checked fifth segment: non-empty, at most [`LABEL_MAX_LEN`] chars,
/// ASCII alphanumeric and starting with a letter — the atproto NSID name
/// rules, which camelCase satisfies and a hyphen does not.
///
/// Feeds [`Name`] through `From<ClaimName>`; a word this build does not
/// know becomes [`Name::Other`]. Built through [`FromStr`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ClaimName(String);

impl ClaimName {
    /// The name verbatim.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Display for ClaimName {
    /// The name verbatim — what was checked is what is rendered.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for ClaimName {
    type Err = CodecError;
    /// Check the name segment's syntax. Shape only; any well-formed name is
    /// accepted, known or not.
    fn from_str(name: &str) -> Result<Self, Self::Err> {
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
        Ok(Self(name.into()))
    }
}

/// The checked authority — segments 1–2, `<tld>.<domain>`: exactly two
/// [`ClaimLabel`]s joined by a dot, the reversed domain that owns a kind's
/// meaning.
///
/// Feeds [`Authority`] through `From<ClaimAuthority>`; a domain this build
/// does not know becomes [`Authority::Other`]. Built through [`FromStr`],
/// or by the kind parser from two labels it has already checked.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ClaimAuthority(String);

impl ClaimAuthority {
    /// The `<tld>.<domain>` string verbatim.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Join two labels the parser has already checked; no re-check.
    fn from_labels(tld: ClaimLabel, domain: ClaimLabel) -> Self {
        Self(format!("{tld}.{domain}"))
    }
}

impl Display for ClaimAuthority {
    /// The authority verbatim — what was checked is what is rendered.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for ClaimAuthority {
    type Err = CodecError;

    /// Exactly two dot-separated labels, each checked as a [`ClaimLabel`].
    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        let (tld, domain) = raw
            .split_once('.')
            .ok_or_else(|| invalid("authority needs two segments (tld.domain)"))?;
        if domain.contains('.') {
            return Err(invalid(
                "authority has more than two segments; expected tld.domain",
            ));
        }
        Ok(Self::from_labels(tld.parse()?, domain.parse()?))
    }
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
        let mut segments: Vec<&str> = raw.split('.').collect();
        if segments.len() != SEGMENTS {
            return Err(invalid(format!(
                "expected {SEGMENTS} segments (tld.domain.protocol.category.name), found {}",
                segments.len()
            )));
        }
        let claim_name = segments
            .pop()
            // A NONE here means empty string. Already impossible with the previous check
            .ok_or(CodecError::NonCanonical)?
            .parse::<ClaimName>()?;

        let segments = segments
            .into_iter()
            .enumerate()
            .map(|(i, label)| {
                label
                    .parse::<ClaimLabel>()
                    .map_err(|err| invalid(format!("segment {i}: {err}")))
            })
            .collect::<Result<Vec<ClaimLabel>, CodecError>>()?;
        // Four labels remain after the name was popped; the count was
        // checked above, so this cannot fail.
        let [tld, domain, protocol, category]: [ClaimLabel; SEGMENTS - 1] =
            segments.try_into().map_err(|_| CodecError::NonCanonical)?;
        Ok(Self {
            authority: Authority::from(ClaimAuthority::from_labels(tld, domain)),
            protocol: Protocol::from(protocol),
            category: Category::from(category),
            name: Name::from(claim_name),
        })
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
    /// `ClaimKind(<wire form>)` — a kind reads better whole than as four
    /// derived fields.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ClaimKind({self})")
    }
}

impl Serialize for ClaimKind {
    /// One text string — the [`fmt::Display`] wire form, so DAG-CBOR
    /// carries exactly the bytes that were parsed.
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for ClaimKind {
    /// A text string through the [`FromStr`] parser — decode is guarded by
    /// the same syntax check as [`ClaimKind::parse`], and an unknown value
    /// still decodes.
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
                matches!(k.authority(), Authority::Other(a) if a.as_str() == "com.example")
                    && k.is_acp()
                    && k.category() == &Category::Identity
                    && matches!(k.name(), Name::Other(n) if n.as_str() == "foo")
            }),
            ("net.got-paws.acp.consent.artwork", |k: &ClaimKind| {
                k.authority() == &Authority::GotPaws
                    && matches!(k.category(), Category::Other(c) if c.as_str() == "consent")
            }),
            ("net.got-paws.xyz.identity.email", |k: &ClaimKind| {
                !k.is_acp()
                    && matches!(k.protocol(), Protocol::Other(p) if p.as_str() == "xyz")
                    && k.name() == &Name::Email
            }),
            (
                "net.got-paws.acp.identity.newThing",
                |k: &ClaimKind| matches!(k.name(), Name::Other(n) if n.as_str() == "newThing"),
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
            Authority::from("com.example".parse::<ClaimAuthority>().unwrap()),
            Protocol::Acp,
            Category::Identity,
            Name::from("foo".parse::<ClaimName>().unwrap()),
        );
        assert_eq!(dynamic.to_string(), "com.example.acp.identity.foo");
        assert_eq!(ClaimKind::parse(&dynamic.to_string()).unwrap(), dynamic);
    }

    #[test]
    fn segment_enums_speak_the_wire() {
        let authority = |s: &str| s.parse::<ClaimAuthority>().unwrap();
        let label = |s: &str| s.parse::<ClaimLabel>().unwrap();
        let name = |s: &str| s.parse::<ClaimName>().unwrap();
        assert_eq!(
            Authority::from(authority("net.got-paws")),
            Authority::GotPaws
        );
        assert_eq!(
            Authority::from(authority("org.other")).as_str(),
            "org.other"
        );
        assert_eq!(Protocol::from(label("acp")), Protocol::Acp);
        assert_eq!(
            Category::from(label("relationship")).to_string(),
            "relationship"
        );
        assert_eq!(Name::from(name("externalAccount")), Name::ExternalAccount);
        assert_eq!(Name::from(name("other")), Name::Other(name("other")));
        // The unchecked string never reaches an enum: bad syntax fails at
        // the newtype door, so an `Other` is always a parseable segment.
        assert!("external-account".parse::<ClaimName>().is_err());
        assert!("com".parse::<ClaimAuthority>().is_err());
        assert!("com.example.extra".parse::<ClaimAuthority>().is_err());
        assert!("com..".parse::<ClaimAuthority>().is_err());
        assert!("Com.example".parse::<ClaimAuthority>().is_err());
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
