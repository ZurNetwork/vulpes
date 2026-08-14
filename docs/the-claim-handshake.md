# The Claim Handshake

*A ground-up derivation of the ACP. Written by hand first (the Supernote
notebook `Dev/vulpes/Handshake.note`, 2026-08-13); this is the faithful
transcription. Where the [explainer](explainer.md) walks through the protocol
as it is, this document derives it — each mechanism appears only when the
previous design visibly fails. The six axioms it lands on are canonized in
the [spec](acp.md#design-principles-the-axioms).*

*Terminology note: the handwritten original names the vouching party the
"Issuer" (and once, memorably, the "Attestator"). This transcription uses the
spec's term, **attestor**; nothing else was changed.*

---

## The handshake

One of the coolest, but most painful things about decentralization, is how
independent nodes are.

Humans, by nature, are decentralized systems too. We are all different units
of computing.

A PDS (`@://`) and a person (IRL) are pseudo-independent, isolated pieces of
storage and computing. **Thinking about PDSs (Personal Data Servers) as
human-like entities makes everything much easier to design.**

Let's take the following example:

1. A person applies for a job.
2. The person claims certain stuff, canonical according to them ("great at
   parties", "son of George Washington"). It is up to the company to believe
   this person at face value.
3. If the company feels like they need to double-check the information this
   person is offering, they may call one of the person's references.
4. The reference may vouch for the person, or they might not.
5. It is up to the company to believe the voucher or not. **This is a
   "Claim."**

Nobody is saying that the reference in this example is telling the truth,
exactly like in real life. The company has to decide whether they accept the
person or not. The system, which is just claims, is what allows this to
happen.

However, let's notice what actually happened:

1. The person applying is the one **initiating** the action.
2. The company only has a reference to something else for the vouch
   **because the person gave them implicit permission to call them, and how
   to contact them.**
3. The company may still decide it doesn't believe the vouch and reject out
   of mistrust — or not even call for a vouch and just go with it.

This is the true magic of it: we accept that things may be lying, for
whatever reason. Humans have been doing it since forever. In a decentralized
system, like the `@://`, it is very similar:

1. A PDS fetches something from a system.
2. The system asks another PDS B if PDS A *is* something (like: over the age
   of 18?).
3. PDS B replies with a yes or a no.
4. The system fulfills or denies the request.

Importantly, this system — which is a first iteration of what it should be —
has a major problem.

## And so, what's the problem?

You may notice that the fetch step requires two things:

1. The PDS being asked **exists**.
2. The PDS being asked is **responding**.

In the world of decentralization, I have defined a couple of specific
axioms. The first one, we've already discussed:

> **Axiom 1: Everybody may be lying, for no apparent reason at all.**

Have you ever met someone that just seems to be lying all the time for no
apparent reason? It drives me crazy. ("I lost my leg fighting a Canadian.")
As entertaining as such people may be, it is up to you if you decide to
believe them or not.

A friend may vouch for them — but what if the friend *would*, but is not
there to do so?

Things like this may exist in the real world. Let's look into the distant
past for an example.

## The letter

You are a king that lives peacefully with his neighbors. One day, a
messenger arrives with a letter from one of your feudal friends:

> Dear Chee,
>
> It has come to my attention that your royal adviser is plotting a
> revolution against you.
>
> My spies confirmed it and I communicate it to you.
>
> Always yours,
> King Snep

There's several things that could be false about this singular note:

1. Your friend may be lying.
2. The note may have been forged.
3. The king's spies were wrong.
4. The king's spies were lying — totally possible for a vouch.

Taking action against your adviser may be a political play from your friend
to weaken a contradictory person that has potential issues with them.

**Everybody could be lying.**

But, let's notice something: you can't ask your friend just like that.
Messages were not instant before, and checking if the message is true may as
well cost you your life.

This brought up the second iteration of our design:

> **Axiom 2: Valid claims may be made by entities that no longer exist, or
> may just be unreachable.**

You decide to believe that the note is true because of who sent it — but
most importantly, because it's **current**.

## The consensual claim

Claims in our PDS system allow for a PDS to attach the claim to the receiver
of each claim, **consensually**:

1. PDS A → PDS B: "Can you say I'm 18?"
2. PDS B → PDS A: "Proof?"
3. PDS A → PDS B: "Sure!"
4. PDS B → PDS A: "OK!"

The result: *PDS B's DID claims that PDS A is over the age of 18* — signed.

But… what about claims that are not simply permanent? Well, they need to be
current:

> "PDS B claims X about PDS A **until Y**."

Claims may have expiration dates. This expiration date cannot be forged into
a previous claim without breaking the signature. Like a JWT!

## The payoff

And so the system from the first example **no longer requires PDS B**.
Claims always live in the **subject's** PDS:

1. System fetches from PDS A.
2. "Proof?" — 3. "Sure!" — 4. "OK!"

**PDS B never got asked anything.**

The only role of PDS B is to continue issuing the same claim when it
expires, under request. How is it issued? Up to whoever owns the PDS! Going
forward, we are going to call PDS B the **attestor**.

Notice though that we have a new problem: **revocation**. An attestor that
makes a claim for a long time may decide that it was an error. Because of
this, **short-lived claims are preferred**. However, it is not wise to
believe that everybody will follow this instruction for every PDS — so
claims have **types**.

## Passive claims

Passive claims, or temporal claims, are the type of claims we already
explored. They are claims that exist with a specific expiry date. An example
of a claim like this may be a certification that needs to be renovated — a
driving license, expiring in 10 years. Yet again, notice how there is a
literal real-world analog to these claims.

## Active claims

Active claims are claims that exist in the PDS of both the attestor and the
attested. A system may see the claim, signed and everything, in the
attested's PDS — but this claim is an attestor saying *"this claim may
change from one minute to the next; please, ask me if possible."*

If the attestor doesn't respond, it is up to the system to decide what to do
with the asymmetric system. A keycard to your job may be valid from one
moment to the next. An invalid keycard may lock you out — or not.

## Permanent claims

Arguably the most dangerous type of claims, as they cannot be revoked
without consent. The attestor has to request the attested to remove the
claim, which they may refuse.

Imagine giving your friend $20 cash. Other than bruteforce, you need their
consent or some authority to give you back those dollars. **And they may be
unable to.**

Permanent claims are generally discouraged. Even the claim "attested is +18"
may be due to falsified documents. Permanent claims exist as a natural
effect of how claims work. Better to mention and inform than ignore them
completely.

## Important

Inevitably, systems may not follow said suggestions for types. A system may
treat passive claims as active, or may even accept expired ones. The types
just make it easier for a system to choose based off the attestor's
recommendation — which brings us to our next axiom:

> **Axiom 3: Systems decide how to process data under their own rules.**

The data may only suggest — but decentralization means that rules also apply
differently everywhere. Standards can be suggested, but enforcing them is
hard. **Democratization of processing is how we fight centralization.** A
passport may not work for every country.

## Forgery

Let's go back to the example of the license. In one of my favorite clips of
*Parks and Recreation*, Ron Swanson produces a "permit" to someone asking to
see it. The permit only says:

> "I can do what I want."

Obviously, that gets rejected — but let's say that the permit was an actual
permit… or even better: a plain **I.O.U.**

A plain IOU, without anything else, may be completely copied by another
party — and the issuer (in this case also the system) won't know any better.
**Any document without a subject in its contents can be copied into any
place.**

Because of this, a claim needs, FIRST OF ALL, to add **who the claim is
directed to**. Otherwise it might as well be an adornment: a signed check
without a "To:" line. (From: Million Dollar Company. Amount: $7,000.
To: ______. — Dunce.)

And suddenly, two PDSs cannot have the exact same bytes AND be valid: either
the subject is wrong, or the signature demonstrates forgery.

But claims may be perfectly copied, and the system may see them in
isolation:

1. PDS B **copies** PDS A's claim into its own repo.
2. System fetches; sees `subject = PDS A`.
3. "Proof?" — "Sure, I am A." — "OK!"

PDS B got what it wanted, because the system saw the subject as PDS A and
didn't know that it was PDS B the one making the request. **We essentially
got our identity stolen.**

The way to verify this is by using an injected, **not persisted**, key
called:

## `$sig.repository`

This is an injected property that is calculated by **both** the system and
the attestor.

**This signature NEVER travels.** That would defeat the purpose. Because of
this, an attacker would need to forge the signature somehow — extremely
difficult.

Notice the most important part: **only the attestor and the system calculate
it.** (Largely speaking, this system is a lot more complex, and I would
recommend looking it up rather than expecting me to explain it totally.)

However, imagine it like this: the system and the attestor reach the same
key based off **the DID of the attested**. Since the attestor knows *who it
is for*, they can use that DID to sign it. Since the system knows *who is
asking*, they can use that DID to generate the hash.

If the claim is served by the repo that got it originally:

> **f(x) = g(x)**

…because the DID is exactly the same. Forgery would change the subject, the
signature, and the `$sig.repository` generated. And so:

> **Axiom 4: Information that is not explicit may as well not be information
> at all.**

And:

> **Axiom 5: Information for claims must be signed. Always.**

## Identity

Let's go back to the analogy we had before, with the company hiring you.
Let's say that your main reference is another company, but — as companies
often do — it bankrupted and can no longer be asked.

The only thing that survives is their legal record.

The company trying to hire you may try to ask them, and react however they
desire when they do not get a response. They may say: *"oh well — they don't
exist anymore, but their signature seems correct."*

Which is the same thing that survives on a deleted attestor: **their DID.**

> **Axiom 6: Referenced data is never to be treated as permanent, but rather
> as temporary. Absence doesn't mean malice.**

This is why asymmetric signing and operations are so important:

> **An attestor may fuck off** (often without notice) —
> **but their history remains, only, in their DID.**

In a very beautiful way, identity survives and transcends existence of a
PDS.

Now *that's* beautiful.
