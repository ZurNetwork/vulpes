# The ACP, explained

*A developer's walkthrough of the Attested Claims Protocol. The values are in
the [manifesto](manifesto.md); the normative details are in the
[spec](acp.md). This document is the bridge: one worked story, real records,
and the differences from the things you already know.*

---

## The idea in one paragraph

In Guatemala there's a concept called **conectes**: you get a job because
someone told someone else you're an incredible engineer. Nobody consults a
registry; the vouch is a person's word, staked on their name, and the
listener decides what it's worth. The ACP is conectes made verifiable: **you
state facts about yourself in a space you hold the keys to; anyone who
checks a fact can sign a vouch for it, which you keep; anyone else can
verify who vouched, for what, and until when — without asking any central
service, or even the voucher.** The voucher can vanish entirely and the
vouch still checks out.

## A worked story

Kit is an artist. An art marketplace wants proof that Kit controls the email
on their commission page before listing them. Three parties, three steps, no
platform in the middle.

### Step 1 — Kit states the fact (a self-claim)

Kit's agent writes a record into **Kit's own repo** (their PDS — the same
kind of repo Bluesky posts live in):

```json
{
  "$type": "net.got-paws.acp.claim",
  "kind": "net.got-paws.acp.identity.email",
  "payload": { "address": "kit@example.com" },
  "createdAt": "2026-08-11T20:00:00.000Z"
}
```

This record now has an address and a content hash:

```
uri: at://did:plc:kit123.../net.got-paws.acp.claim/3kx2vp5qmek2h
cid: bafyreib2wqx5dpztluczpdxkkzgcp3xa4e3xolvqmyc5zaq
```

It proves nothing yet. Anyone can claim any email. That's fine — claiming is
free by design.

### Step 2 — an attestor checks it and vouches (an attestation)

Kit asks an attestor — say `attest.vulpes.example`, or any other service or
person running the same open machinery — to verify the claim. The attestor
emails a challenge link to `kit@example.com`; Kit clicks it. The attestor
now signs a vouch **bound to Kit's exact claim record by content hash**:

```json
{
  "$type": "net.got-paws.acp.attestation",
  "subject": "did:plc:kit123...",
  "claim": {
    "uri": "at://did:plc:kit123.../net.got-paws.acp.claim/3kx2vp5qmek2h",
    "cid": "bafyreib2wqx5dpztluczpdxkkzgcp3xa4e3xolvqmyc5zaq"
  },
  "attestor": "did:plc:attestor456...",
  "issuedAt": "2026-08-11T20:05:00.000Z",
  "expiresAt": "2026-09-11T20:05:00.000Z",
  "method": "email-challenge",
  "sig": "…signature over this object minus sig, DAG-CBOR canonical…"
}
```

The attestor hands the signed object to Kit, and **Kit writes it into Kit's
own repo**. Two signatures now protect it: the attestor's signature inside
the record (the truth), and Kit's repo signature around it (the custody).
The attestor keeps no copy that matters.

Notice `expiresAt`: one month. Email control is volatile and mechanically
checkable, so the vouch is short-lived and Kit's agent auto-renews it — the
attestor re-runs the challenge and re-signs. Validity is a pulse, not a
stored fact.

### Step 3 — the marketplace verifies (no phone calls)

The marketplace's verifier, given Kit's DID:

1. Lists `net.got-paws.acp.attestation` records in Kit's repo (one standard
   `com.atproto.repo.listRecords` call — the subject's repo is the index of
   everything they've accepted).
2. Fetches the referenced claim; checks its CID matches. (If Kit had edited
   the claim after the vouch, this fails — content-hash binding means every
   vouch visibly detaches from anything but the exact version it checked.)
3. Resolves `did:plc:attestor456...` in the PLC directory → gets the
   attestor's public key from its DID document.
4. Verifies the signature. Checks `expiresAt` is in the future.
5. Decides whether it *trusts this attestor* for email claims. That last
   step is policy, not protocol — the marketplace might accept
   `attest.vulpes.example`, or only its own attestor, or any of a list.

No call to the attestor. No call to any Vulpes service. If the attestor
shut down yesterday, steps 1–4 work identically — the key is in the PLC
directory, the record is in Kit's repo. Kit has a month to get re-vouched
elsewhere, and life goes on. **That's the kill test, and every piece of the
protocol is shaped by it.**

## "But what if the voucher is just Kit's friend?"

Then the marketplace says: *we don't accept that voucher — we accept these.*
Trust lives entirely at the edge. The protocol never rules on truth; it
authenticates **who said what, about what, when, and whether it still
stands**, and every verifier applies its own policy about whose word counts.
Anyone can vouch; nobody must be believed. Exactly like a conecte — except
the vouch is inspectable by anyone, and you don't need to be well-connected
to get one: the diligence machinery is open for anyone to run.

## Consent is the write permission

A vouch lands in *your* repo, written by *you*. Nobody can deposit a claim
into your identity — not "+18", not "great engineer", not anything — because
they can't write to your repo. What someone says about you in *their* repo
is their speech (ATProto already has that: follows, labels); ACP just never
confuses it with *your* record. And for claims that inherently bind two
parties — ownership, membership — nothing new is needed: you claim the
relationship in your repo (one kind for both sides; your payload says which
side you are), and the *other* party is the one who vouches for it. No vouch, no relationship. You end it by deleting your claim; they end
it by withdrawing their vouch — each unilaterally, neither touching the
other's repo.

## How this differs from what you know

**vs. ATProto labels** — a label is a broadcast *about* you, hosted by the
labeler, no consent required, gone when the labeler is. An attestation is
held *by* you, exists only with your consent, expires on schedule, and
survives its issuer. Labels are speech; attestations are your papers.

**vs. W3C Verifiable Credentials** — same trust triangle (issuer → holder →
verifier), and deliberately compatible in shape (claims are VCDM-style
envelopes). But ACP v0.1 is *public-lane only*: records in public repos,
no selective disclosure, no ZK. The private lane (SD-JWT-VC/BBS via OID4VP)
is the planned complement for claims whose *existence* must stay private.
If you know VCs: ACP is the VC triangle with ATProto as the registry,
custody, and transport — and radical simplicity as the price of shipping.

**vs. "Sign in with Google"** — OAuth proves *account possession at one
provider, live, every time*. ACP proves *arbitrary facts, offline, from
whoever you choose* — and the provider's death doesn't lock you out of
your own identity.

**vs. JWTs** — an attestation basically *is* one, philosophically:
`{iss, sub, exp, sig}` verified offline. Two upgrades: key discovery goes
through the PLC directory instead of the issuer's JWKS URL (so verification
outlives the issuer), and claims are bound by content hash (so tampering
with the claimed fact visibly detaches every vouch on it).

## Frequently asked

**How do I revoke a vouch I issued?** Decline to renew it (short-lived
kinds), or flip its bit in your published status list (long-lived kinds).
You never reach into the subject's repo.

**How do I remove a vouch about me?** Delete the record. It's your repo.

**What if my attestor disappears?** Your vouches remain verifiable until
they expire; you re-attest with anyone else before then. Inconvenience,
not breaking factor — by design, no attestor is allowed to matter more
than that.

**Who can see my claims?** Everyone. The v0.1 public lane is public —
publishing a claim is publishing a link, and that's the point of
publishing. Claims that need private *existence* wait for the private
lane; don't put them in public records with obscure names.

**Where's the server I run?** There isn't one you must run. Subjects need
a PDS (any ATProto host). Attestors run the open attestor machinery — the
Vulpes library — or use a hosted instance, which holds no privileged
position and can be left at any time.

---

*Next layer: the reference implementation — the `vulpes` crate.*
