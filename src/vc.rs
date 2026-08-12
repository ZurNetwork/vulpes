//! The wrapped credential stack — SpruceID's `ssi`, curated.
//!
//! Nothing in the ACP public lane needs this module; it exists so the private
//! lane (holder-held VC 2.0 / SD-JWT-VC) will build on a foundation that was
//! version-locked and feature-pruned deliberately rather than adopted in a
//! hurry. The pruning is the point: BBS and every non-atproto curve are OFF —
//! what isn't in the build can't be an attack surface.
//!
//! No credential code is hand-rolled here (the machinery ruling: wrap what's
//! healthy, hand-roll only the real gap). This module only narrows what `ssi`
//! exposes; widening it back is a deliberate edit to this file, not a feature
//! flag flipped elsewhere.

/// JSON Web Keys — the key representation the claims machinery signs with.
pub use ssi::JWK;
/// Claims machinery: the W3C Verifiable Credentials data model, JOSE
/// (JWS/JWT), and SD-JWT.
pub use ssi::claims;
/// DID resolution and DID-document types.
pub use ssi::dids;
