# Recovery Model — Comparative Design

## Topic

This page covers recovery models for multi-device identity.

## Status

- **Started:** 2026-04-13
- **Stage:** `Drafting`
(`Drafting` / `In discussion` / `Stabilizing` / `Stabilized`)

## How to use this page

- Each contributor fills their own section first
- DO NOT edit each people's section - only comment.
- To respond to someone else, add an inline note formatted as `> [your-handle] response text` directly under the line you're responding to.
- The **Convergence** section at the bottom is *only* for things we've all agreed on. Don't put hot takes there.

---

## isi

### Current design

What auths does today, with code/spec links where useful. Be specific — file paths, function names, behavior, not just intent.

**Event Field Lables**

| Key | Value Description           		    |
|:---:|-----------------------------------------|
|  t  | Event Tag                   			|	
|  i  | Log Identity                			|
|  p  | Prior Event Said              			|
|  e  | Current Event Said            			|
|  s  | List of Signing Keys        			|	
|  st | Signing Threshold  						|
|  r  | List of Rotation / Recovery Hashes   	|
|  rt | Rotation / Recovery Threshold  			|
|  a  | List of Seal Anchors				    |

**Recovery Event Example**

```json
{
    "t": "sign_v1/rec/3",
    "i": "BPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB",
    "p": "BPD7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB",
    "e": "BPK7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB",
    "s": [
        "EBFiTgoCOpJ_zW_OO0GdffBhHfEvJWb1HxpDx95bFvufu",    // device_3 public signing key (first key)
        "EBFiTgoCOpJ_zW_OO0GdffBhHfEvJWb1HxpDx95bFvufu"     // backup_1 public signing key
    ],
    "st": ["1", "0"],                                       // notice the signing weight for the "recovery key" is 0
    "r": [
        "BLeFXBmuJb0hevKjhv97joA5bTfuA8E697cMzi8eoaZB",     // device_3 rotation hash (second key)
        "BLeFXBmuJb0hevKjhv97joA5bTfuA8E697cMzi8eoaZB"      // backup_2 recovery hash
    ],
    "rt": ["1", "1"]
}
```

![example(3)](https://hackmd.io/_uploads/HJgmSninbe.png)

### Design intent

Why it's built that way. What tradeoffs were taken consciously. What you'd defend vs. what you'd revisit.

**tl;dr** recovery keys should ONLY ever be used to sign recovery events and an extra recovery event makes it easier for applications to handle processes like recovering encrypted group membership

- Recovery keys are usually less secured as they have to be stored outside of the linked devices (mnemonic, cloud hsm, synced passkey, ...). In conclusion once a recovery key is used / exposed, it should never be used for signing `inx` events or authenticate the identity as they are less secured compared to device signing keys which are usually secured by enclaves. Introducing a `rec` event that makes sure that the current signing weight (also called execution authority) for the exposed recovery key is 0 and using keyed hashes (e.g. `blake3::keyed_hash("recovery", "<public_key>")`) in order to derive the recovery hash for pre-commitment, achieves this goal. Now, recovery keys can only be used for recovering the identity kel.

- Another reason for an extra `rec` event is the following case. Imagine an encrypted group where only members can add or remove each other. Let's say you have a group of two users and one user looses access to all his devices. If the user had still access to one of his devices, he could just link a new device by doing a rotation and then sign themselves into the encrypted group. However since that is not the case, he needs to do a recovery to link a new device. The difference from a normal rotation (linking / unlinking) is that the user has no way to add the newly linked device to the encrypted group on his own. That means that the other existing group member needs to add him. By introducing an extra recovery event, it's easier for the system to inform existing users that a recovery happened, so they can approve and add the new device to the group.

### Known weaknesses / open questions

What you'd flag yourself before others ask. What you don't know how to solve yet.

- Divergence is not handled natively as in KELS or with the help of witnesses as in KERI. My design requires a registry to resolve that. Currently a registry works similarly to a transparency log as described in https://transparency.dev and can be compared to the https://plc.directory from atproto.

---

## rank5.syzygy / jasoncolburne (kels)

## Current design

### Setting up a multi-device identity

A user (Alice) has 3 devices: laptop, phone, desktop. Each device incepts its own KEL with its own key set held in hardware (Secure Enclave, etc.).

```
# Each device incepts independently
# Device generates P256/ML-DSA-65/ML-DSA-87 keypairs in hardware, commits to next key via rotation_hash and recovery key via recovery_hash

Device: laptop  → icp → prefix: Klaptop_prefix______________________________
Device: phone   → icp → prefix: Kphone_prefix_______________________________
Device: desktop → icp → prefix: Kdesktop_prefix_____________________________
```

Each inception event establishes cryptographic commitments:
- `public_key` — current signing key (ML-DSA-65 verification key)
- `rotation_hash` — Blake3 hash of the *next* signing key (pre-rotation commitment, revealed during rotations)
- `recovery_hash` — Blake3 hash of the recovery key (recovery key commitment, revealed only when needed)

The recovery key exists only as a hash commitment until a recovery-class event (`rec`, `ror`, `cnt`, `dec`) requires its revelation.

### Creating the identity policy

Alice creates a threshold policy requiring 2-of-3 device endorsements:

```
# Policy DSL expression
threshold(2, [endorse(Klaptop_prefix______________________________), endorse(Kphone_prefix_______________________________), endorse(Kdesktop_prefix_____________________________)])
```

This becomes a `Policy` SAD:

```rust
// lib/policy/src/policy.rs
Policy {
    said: KPolicyV1Said_______________________________,  // derived
    expression: "threshold(2, [endorse(Klaptop...), endorse(Kphone...), endorse(Kdesktop...)])",
    poison: None,    // default: any endorser can withdraw
    immune: None,    // not immune
}
```

The policy is stored in SADStore as a SAD object.

### Creating the identity chain

The identity chain is a SAD pointer chain with topic `kels/sad/v1/identity/chain` and `write_policy` set to the policy's SAID. Content is `None` at every version — the policy reference lives in `write_policy`.

Since identity chains are not discoverable by third parties (the owner knows the prefix; peers learn it via credential presentation), v0 can carry `checkpoint_policy`. This avoids needing a separate `Est` record and keeps the chain compact.

```rust
// Pointer chain v0 (inception):
SadPointer {
    said: <derived>,
    prefix: <derived>,          // stable identity — see derivation below
    previous: None,
    version: 0,
    topic: "kels/sad/v1/identity/chain",
    kind: SadPointerKind::Icp,
    content: None,
    custody: None,
    write_policy: KPolicyV1Said_______________________________,
    checkpoint_policy: KCheckpointPolicySaid____________________,  // higher threshold
}
```

The pointer prefix is Alice's **stable identity**. It's derived via standard KELS prefix derivation: the v0 pointer is serialized to JSON with `said` and `prefix` set to 44-char placeholders (`"#" * 44`), then Blake3-hashed. Since v0 has no `content`, `previous`, or `custody`, the prefix is determined by `write_policy`, `checkpoint_policy`, `kind`, and `topic`. Anyone who knows these values can compute the prefix offline:

```rust
// lib/kels/src/types/sad/pointer.rs
let prefix = compute_sad_pointer_prefix(policy_said, "kels/sad/v1/identity/chain")?;
```

Note: `compute_sad_pointer_prefix` creates a v0 template with `checkpoint_policy: None`. If v0 carries `checkpoint_policy`, the actual prefix differs from what `compute_sad_pointer_prefix` returns. This is intentional — identity chains are not meant to be discovered via prefix computation. The prefix is learned from the credential or shared out-of-band.

Credentials, services, and peers reference this prefix. It never changes.

### Checkpoint policy

Checkpoint policy bounds divergence on the identity chain. An adversary who compromises `write_policy` (enough device keys to meet the threshold) can fork the chain, but their fork is bounded to 63 records before requiring a checkpoint they cannot produce.

The checkpoint policy **must be a higher threshold** than the write policy — otherwise an adversary who satisfies write_policy automatically satisfies checkpoint_policy, defeating the purpose. The recoverability invariant (M < N) still applies to both policies.

The simplest approach is the same endorser set with different thresholds. With 4 endorsers:

- Write: `threshold(2, [A, B, C, D])` — 2-of-4, day-to-day operations
- Checkpoint: `threshold(3, [A, B, C, D])` — 3-of-4, sealing and repair

An adversary who compromises 2 devices satisfies write but not checkpoint. Their fork is bounded to 63 records. The legitimate owner (controlling 3+ devices) can produce checkpoints and repair.

With only 3 devices this doesn't work — 2-of-3 write leaves no room for a higher threshold that survives device loss (3-of-3 means losing one device locks you out of checkpointing). Three devices require either adding a 4th endorser (cold storage key, hardware token) or accepting that checkpoint_policy equals write_policy (no divergence bounding beyond the structural 63-record limit).

### Endorsing the policy

Each device anchors the policy's SAID in its own KEL via an interaction event:

```
# Each device signs the policy SAID and anchors it
laptop:  ixn → anchor: KPolicyV1Said_______________________________
phone:   ixn → anchor: KPolicyV1Said_______________________________
desktop: ixn → anchor: KPolicyV1Said_______________________________
```

Any 2 of these anchors satisfies `threshold(2, [...])`. The policy is now live.

### Typical identity chain shape

```
v0  [Icp]  write_policy=threshold(2,[A,B,C,D]), checkpoint_policy=threshold(3,[A,B,C,D])
v1  [Upd]  write_policy=P2 (advance after device loss/addition)
v2  [Evl]  (periodic checkpoint to seal the chain)
...
v8  [Upd]  write_policy=P3 (another policy evolution)
v9  [Evl]  (checkpoint — seals v0-v9)
```

Identity chains advance rarely (device changes, policy updates), so the 63-record checkpoint bound is not a practical concern.

### Reference Image (not sure this is the best depiction now)

![Identity, Policy and Devices](https://hackmd.io/_uploads/HkDbLgpnWe.png)

### Losing a device (phone stolen)

Alice loses her phone. She wants to remove the phone and add a tablet.

**Step 1: Create new policy P2**

```
threshold(2, [endorse(Klaptop...), endorse(Kdesktop...), endorse(Ktablet_prefix______________________________)])
```

**Step 2: Advance the identity chain**

Write pointer chain version 1 with `write_policy: P2_SAID`. This advance is authorized by P1 (the v0 `write_policy`) — Alice's laptop and desktop both anchor the new pointer's SAID, satisfying the 2-of-3 threshold.

```rust
SadPointer {
    said: <derived>,
    prefix: <same chain prefix>,  // unchanged
    version: 1,
    topic: "kels/sad/v1/identity/chain",
    kind: SadPointerKind::Upd,
    content: None,
    custody: None,
    write_policy: KPolicyV2Said_______________________________,
}
```

The pointer prefix is unchanged. All credentials referencing Alice's identity still work. The current policy is now P2 — the phone is no longer an endorser. The phone's KEL is abandoned — it can't be decommissioned without access to the device's keys.

### Three levels of key compromise

#### Level 1: Signing key compromised (recovery key intact)

**Scenario:** A future cryptanalytic advance weakens ML-DSA-65. An adversary derives Alice's laptop signing key from observed signatures. Alice still has her device — the next signing key and recovery key are independently generated and unaffected.

The adversary submits forged `ixn` events to the laptop's KEL (they can't `rot` — that requires the pre-committed next key, which they don't have). When any node receives both the legitimate and adversary events at the same serial, it detects **divergence**. The KEL's effective SAID becomes `hash("divergent:Klaptop_prefix...")` — deterministic across all nodes.

**Resolution: recovery (`rec`)**

Alice submits a `rec` event, dual-signed with the signing (rotation) key and the recovery key:

```rust
// lib/kels/src/types/kel/event.rs — create_recovery()
KeyEvent {
    kind: Rec,
    prefix: Klaptop_prefix...,
    serial: <divergence serial>,
    public_key: <new signing key>,
    rotation_hash: <hash of next signing key>,
    recovery_key: <revealed recovery key>,
    recovery_hash: <hash of next recovery key>,
    // Dual-signed: signatures["signing"] + signatures["recovery"]
}
```

The merge engine archives all adversary events synchronously and installs new keys. The KEL is clean again. No identity chain advance needed — the laptop is still a valid device with new keys. The adversary is bounded to ≤62 forged events by the proactive ROR invariant (`MINIMUM_PAGE_SIZE - 2`).

#### Level 2: Rotation key compromised

**Scenario:** The adversary compromises the rotation key. The adversary submits their own `rot` event, followed by another. After the second, the signing key is no longer known to the owner. The adversary can extend the KEL arbitrarily at this point.

**Resolution: recovery (`rec`)**

Alice submits a `rec` event, dual-signed with the signing (rotation) key and the recovery key:

```rust
// lib/kels/src/types/kel/event.rs — create_recovery()
KeyEvent {
    kind: Rec,
    prefix: Klaptop_prefix...,
    serial: <divergence serial>,
    public_key: <new signing key>,
    rotation_hash: <hash of next signing key>,
    recovery_key: <revealed recovery key>,
    recovery_hash: <hash of next recovery key>,
    // Dual-signed: signatures["signing"] + signatures["recovery"]
}
```

The merge engine archives all adversary events synchronously and installs new keys. The KEL is clean again. No identity chain advance needed — the laptop is still a valid device with new keys. The adversary is bounded to ≤62 forged events by the proactive ROR invariant (`MINIMUM_PAGE_SIZE - 2`).

#### Level 3: Recovery key compromised

Now the recovery key is exposed (`ror` or equivalent). Alice cannot submit a second `rec` — once the recovery key is revealed, recovery is no longer possible.

**Resolution: contest (`cnt`)**

Alice submits a `cnt` event, dual-signed with the signing key and recovery key:

```rust
// lib/kels/src/types/kel/event.rs — create_contest()
KeyEvent {
    kind: Cnt,
    prefix: Klaptop_prefix...,
    serial: <divergence serial>,
    public_key: <current signing key>,
    recovery_key: <revealed recovery key>,
    // No rotation_hash, no recovery_hash — the KEL is permanently frozen
    // Dual-signed: signatures["signing"] + signatures["recovery"]
}
```

The KEL is permanently frozen. Effective SAID becomes `hash("contested:Klaptop_prefix...")`. No further events are accepted by any party.

Alice then advances the identity chain to remove the compromised device:

```
threshold(2, [endorse(Knew_laptop...), endorse(Kphone...), endorse(Kdesktop...)])
```

The stable identity prefix is unchanged. Credentials keep working.

#### Summary

| Level | Compromised | Resolution | KEL outcome | Identity chain | Mitigation |
|-------|-------------|------------|-------------|----------------|------------|
| 1 | Signing key | `rec` | Recovers with new keys | No change | Post-quantum algorithms (ML-DSA-65/87), hardware-backed key generation, regular key rotation via `rot` |
| 2 | Rotation key | `rec` | Recovers with new keys | No change | Post-quantum algorithms (ML-DSA-65/87), hardware-backed key generation, regular key rotation via `ror` |
| 3 | Recovery+ | `cnt` | Permanently frozen | Advance: remove device | Independent generation of signing and recovery keys, hardware RNG, pre-rotation commitment limits adversary's ability to predict next key |

### Device lost or stolen (no access to any keys)

**Scenario:** Alice's laptop is stolen. She has no access to either key. The adversary may or may not extract the keys — it doesn't matter from Alice's perspective.

Alice cannot submit `rec` or `cnt` — she doesn't have the keys. She doesn't need to. The identity chain is the recovery mechanism at this level, not per-KEL cryptographic recovery.

**Resolution: advance identity chain**

Alice's remaining devices (phone + desktop) satisfy the 2-of-3 threshold. She advances the identity chain to remove the laptop and add a replacement:

```
threshold(2, [endorse(Knew_laptop...), endorse(Kphone...), endorse(Kdesktop...)])
```

The laptop's KEL is abandoned. If the adversary later extracts keys and submits forged events, those events are irrelevant — the laptop's prefix is no longer in the identity policy. No honest verifier will accept endorsements from it.

### Identity chain divergence and repair

If the identity chain itself diverges (two competing policy advances submitted at the same version), it follows the standard SAD pointer repair model:

- Divergence is detected, chain is frozen
- The owner submits a `Rpr` record that evaluates against `checkpoint_policy`, proving higher-threshold authorization
- The establishment point (v0 for identity chains, since they carry checkpoint_policy at inception) is immutable — repair can only happen at v1+
- After repair, the chain is sealed at the repair point

See `docs/design/sad-pointers.md` for the full repair model.

## Design intent

**Pre-rotation commitment** prevents rotation key substitution — an adversary who steals a signing key cannot commit to a *new* next key without the rotation hash revealing the fraud at merge time. The legitimate owner committed to their next key at inception/last rotation.

**Dual-signature on recovery/contest** Recovery signature additionally required for higher value operations.

**Bounded divergence** (≤62 adversary events on KELs, ≤63 non-checkpoint records on pointer chains) keeps the damage finite. The proactive ROR invariant is enforced at the merge engine level — nodes reject chains that go too long without a recovery-revealing event. The checkpoint bound is enforced by the SAD chain verifier. Both bound the archival work during recovery/repair.

**Identity chains decouple policy from credentials.** The threshold policy can evolve (add/remove devices, change threshold) without re-issuing every credential. The chain prefix is the stable reference.

**Content is `None` on identity chains** because the policy reference is `write_policy` itself. This is deliberate — the `write_policy` field is what gates the next advance, and for a self-governing identity chain, that IS the current policy. No redundancy.

**Record kinds make chains self-documenting.** Each record's role is visible from its `kind` field without checking field combinations. `Icp` at v0, `Upd` for policy advances, `Evl` for checkpoints, `Rpr` for repairs. The verifier validates structural rules per kind via `validate_structure()` before reasoning about chain state.

**Contest is the last resort, not a failure.** A contested KEL is a clean, deterministic end state. The identity chain can evolve past it by removing the compromised device. The system degrades gracefully — one frozen KEL doesn't take down the identity.

## Poison semantics (credential revocation)

### Current design

"Poison" is kels's revocation mechanism. It operates on credentials, not on KELs. An endorser (or a designated authority) can withdraw their endorsement of a specific credential by anchoring that credential's **poison hash** in their KEL.

```rust
// lib/policy/src/evaluator.rs
// poison_hash = Blake3(b"kels/poison:" || credential_said_qb64_bytes)
pub fn poison_hash(credential_said: &str) -> Digest256 {
    let bytes = [b"kels/poison:" as &[u8], credential_said.as_bytes()].concat();
    Digest256::blake3_256(&bytes)
}
```

To poison a credential, an endorser anchors `poison_hash(credential_said)` in their KEL via an interaction event:

```
# Alice endorsed a credential, now wants to withdraw
alice_kel: ixn → anchor: poison_hash("KCredentialSaid...")
```

### Three poisoning modes on a Policy

A `Policy` has three mutually exclusive poisoning configurations:

**1. Default (neither `poison` nor `immune` set):**
Any endorser named in the policy can poison by anchoring the poison hash. A poisoned endorsement doesn't count toward the threshold — it's a soft withdrawal.

```rust
Policy {
    said: <derived>,
    expression: "threshold(2, [endorse(A), endorse(B), endorse(C)])",
    poison: None,
    immune: None,
}
// If A anchors poison_hash(cred_said), A's endorsement no longer counts.
// B and C must both endorse for the threshold to be met.
```

**2. Custom poison expression (`poison: Some(expr)`):**
A DSL expression defines who can poison and under what conditions. When the poison expression is satisfied, the **entire policy** is unsatisfied — not just one endorsement.

```rust
Policy {
    said: <derived>,
    expression: "threshold(2, [endorse(A), endorse(B), endorse(C)])",
    poison: Some("endorse(Admin)"),  // only Admin can poison
    immune: None,
}
// If Admin anchors poison_hash(cred_said), the whole policy fails.
// A, B, C's endorsements are irrelevant.
```

The poison expression can use thresholds too:

```rust
Policy {
    said: <derived>,
    expression: "threshold(2, [endorse(A), endorse(B), endorse(C)])",
    poison: Some("threshold(2, [endorse(Admin1), endorse(Admin2)])"),
    immune: None,
}
// Both admins must anchor poison_hash for revocation to take effect.
```

**3. Immune (`immune: true`):**
No poison checks at all. Endorsements are permanent and cannot be withdrawn.

```rust
Policy {
    said: <derived>,
    expression: "threshold(2, [endorse(A), endorse(B), endorse(C)])",
    poison: None,
    immune: Some(true),  // no revocation possible
}
```

`poison` and `immune` cannot both be set.

### Design intent

Poison is a **soft revocation** in the default mode — it withdraws one endorsement without killing the credential. If enough endorsements remain, the credential is still valid. This models real-world trust: one party can withdraw support without vetoing the group.

Custom poison expressions model administrative revocation — an authority can kill a credential regardless of endorser support.

Immune policies model permanent grants where revocation would be inappropriate (e.g., a historical attestation).

### The name "poison"

The name is under review. It's technically accurate (it poisons an endorsement's contribution to the threshold) but it reads aggressively and may confuse people unfamiliar with the system. "Revoke," "withdraw," or "retract" are candidates. No decision yet — the semantics are stable, only the naming may change.

## SADStore custody and access control

### Current design

Every SAD object and pointer chain in SADStore can carry a **custody** record — a SAD that controls who can read, where data is stored, and how long it lives. Custody is itself a compactable SAD with its own SAID.

```json
{
  "said": "KCustodySaid________________________________",
  "writePolicy": "KWritePolicySaid____________________________",
  "readPolicy": "KReadPolicySaid_____________________________",
  "ttl": 3600,
  "once": true,
  "nodes": "KNodeSetSaid________________________________"
}
```

Fields (all optional):

| Field | Purpose |
|-------|---------|
| `writePolicy` | Policy SAID that gates who can advance the chain / who authored the record. Consumer-side verified via anchoring. |
| `readPolicy` | Policy SAID that gates who can fetch the record. Server-side enforced via `evaluate_signed_policy()`. |
| `ttl` | Time-to-live in seconds from the record's `created_at`. Server deletes expired records. Only valid on SAD objects, not pointers. |
| `once` | If true, the record is deleted after one successful read. Ephemeral secrets. Only valid on SAD objects, not pointers. Requires `nodes` to be set (for consistent delete-on-read semantics across replicas). |
| `nodes` | SAID of a `NodeSet` — which SADStore nodes should replicate this record. Gossip skips nodes not in the set. Empty `[]` means local-only storage (never gossip). |

### Two enforcement layers

**1. Write authorization (`writePolicy`) — consumer-side, via anchoring:**

Outside of KELs, which are implicitly authorized by virtue of signatures on key events, the `writePolicy` is not enforced by the SADStore server at write time. Anyone can submit a record. Instead, consumers verify at read time that the record's SAID was anchored in the KELs of enough endorsers to satisfy the `writePolicy`. This is the same anchoring model used for credentials — the creator signs by anchoring, verifiers check the anchor chain.

For identity chains, the `writePolicy` on the pointer IS the current policy. An advance from P1->P2 is authorized by checking that P1's threshold was satisfied by anchoring the new pointer's SAID.

**2. Read authorization (`readPolicy`) — server-side, at fetch time:**

The SADStore server enforces `readPolicy` before serving content. The fetch request must be a `SignedSadFetchRequest` signed by a prefix that satisfies the read policy.

```rust
// lib/kels/src/types/sad/request.rs
pub struct SignedSadFetchRequest {
    pub said: cesr::Digest256,
    pub created_at: StorageDatetime,
    pub nonce: cesr::Nonce256,          // replay protection
    pub object_said: cesr::Digest256,
    pub read_policy: Option<cesr::Digest256>,  // signer commits to which policy
    pub disclosure: Option<String>,
}
// Wrapped in SignedRequest<SignedSadFetchRequest> with signatures
```

The server:
1. Verifies signatures on the request (KEL-backed via `verify_key_events`)
2. Checks the signer's prefix against the custody's `readPolicy` via `evaluate_signed_policy()` — this walks the policy AST checking whether the verified prefix set satisfies the threshold, with no anchoring or poison checks
3. Checks `read_policy` on the request matches custody — prevents downgrade attacks
4. Checks TTL expiry
5. If `once: true`, atomically deletes the record and serves it

### Gossip and node sets

SADStore records replicate across nodes via gossip. The `nodes` field controls which nodes participate:

- **`nodes: None`** — replicate everywhere (default)
- **`nodes: Some(KNodeSetSaid)`** — replicate only to the listed prefixes. Gossip checks the `NodeSet` and skips nodes not in it.
- **`nodes: Some(empty_set)`** — local-only, never gossip. Credentials, ephemeral secrets, or records that should stay on one node.

The `NodeSet` is itself a SAD: `{ said, prefixes: [sorted lexicographically] }`. Same set always produces same SAID.

If the `NodeSet` can't be resolved during gossip (e.g., the SAID isn't available), gossip **fails secure** — the record is treated as local-only (`LocalOnly`), not broadcast.

### How this connects to identity and recovery

When Alice creates credentials endorsed by her identity chain's policy, she can attach custody to control access:

```json
{
  "writePolicy": "KAliceIdentityPolicySaid___________________",
  "readPolicy": "KServiceAccessPolicySaid____________________",
  "nodes": "KTrustedNodesSaid___________________________"
}
```

- `writePolicy` references the identity chain's current policy — only Alice's devices (satisfying the threshold) can author records under this custody
- `readPolicy` gates who can read — a separate policy for the service or peer that should have access
- `nodes` restricts replication to trusted infrastructure

After a device compromise and identity chain advance, the new policy automatically governs future records. Existing records retain their original custody — the `writePolicy` SAID still references the old policy. Consumers following the identity chain to the head get the current policy; consumers verifying a specific record check the policy that was current when the record was written.

### Design intent

Two-layer enforcement separates concerns: write authorization is decentralized (anchoring, no central authority), read authorization is server-enforced (the server is trusted to check before serving - possible due to the establishment of trusted peer node agreed upon a federated group of registry operators). This means SADStore can host private data — `readPolicy` prevents unauthorized reads even if the SAID is known.

Custody is a SAD with its own SAID so it compacts cleanly — records sharing the same custody (same policies, same node set) reference the same SAID. Dedup is free.

`ttl` and `once` are restricted to SAD objects, not pointers. Pointers are chained data — expiring or consuming one version would break the chain. Ephemeral use cases (one-time secrets, temporary access tokens) use SAD objects with `once: true`.

## Known weaknesses / open questions

Most of these aren't really 'weaknesses', really just things to be aware of.

**Per-KEL recovery handles signing key compromise.** The primary threat is an adversary who guesses or derives the signing key (weak RNG, side channel, cryptanalytic break) — not device theft. The recovery key is generated independently, so signing key compromise doesn't imply recovery key compromise. The owner submits a `rec` event using the still-intact recovery key. If the device itself is lost or fully compromised (adversary has both signing/rotation and recovery keys), the KEL is contested and removed from the identity chain's policy. The identity chain — not per-KEL key separation — is the device-loss recovery mechanism.

**Contest is permanent and irreversible.** A contested KEL cannot be unfrozen. If the adversary races to contest before the legitimate owner the KEL is dead either way. The identity chain absorbs this by removing the contested prefix from the policy (initiated by a user or automation).

**Identity chain advance requires threshold satisfaction.** If Alice loses 2 of 3 devices simultaneously, she cannot advance the chain — the threshold cannot be met. The mitigation is keeping M < N (e.g., 2-of-3, not 3-of-3). At the harness scale with 3 devices, losing 2 is catastrophic. With 5 devices and 3-of-5, the tolerance improves.

**No automatic detection of signing key compromise.** The system detects divergence (conflicting events), not compromise directly. If the adversary never submits events, the stolen key sits dormant. Regular key rotation reduces the window.

**The `write_policy` on the identity chain is consumer-side verified, not server-side enforced.** The SADStore server stores and serves pointers — it does not evaluate whether the `write_policy` was actually satisfied by anchoring. Consumers (credential verifiers, service access checks) must follow the chain and verify anchoring themselves. A malicious pointer submission with an unauthorized `write_policy` advance will be stored but rejected by any honest verifier.

**Prefix computation for identity chains with checkpoint_policy.** `compute_sad_pointer_prefix` creates a v0 template with `checkpoint_policy: None`. Identity chains that carry `checkpoint_policy` on v0 will have a different prefix than what `compute_sad_pointer_prefix` returns. This is intentional — identity chain prefixes are not discovered via computation, they are learned from credentials or shared out-of-band. But it means the convenience function is not usable for identity chains with v0 checkpoint_policy.

**It's hard to understand when to use identity and when to use policy.** As a concrete example, a ML-KEM key can be specified to facilitate exchange/mail. This key is itself referenced by a sad pointer - but should I bind that key to identity? I chose to use a degenerate policy for this one (but I am wondering if that's best) like `endorse(prefix)` for a single device, but I wonder if it's best to use identity for that reference. To use identity, the model looks different. Every sad can be access controlled in sad store just by applying metadata to it that describes what data custody look like for that object? Should mail and exchange use identity or policy? Probably identity. For most cases, I'd like to use identity. So that is another rework with a ripple effect, and it's actually difficult in some scenarios to use identity and not policy.

---


## bordumb (auths)

### Current design

> All function and file references are hyperlinks.

```json
{
  "v":  "KERI10JSON000000_",
  "t":  "rot",
  "d":  "EuamqHwBLjG2Hhoz6TiYRwsPT6_OVKLtGExx6XxmO3Js",
  "i":  "EZRCNIzUCUvT1rtLf59o26ZTZPKJPgGX_pJHCJ9h-FRw",
  "s":  "1",
  "p":  "EZRCNIzUCUvT1rtLf59o26ZTZPKJPgGX_pJHCJ9h-FRw",
  "kt": "1",
  "k":  ["1AAIAlLEz61nZMN0-ln330vtCba2atD68LfZTRV2SjQ4cZuT"],
  "nt": "1",
  "n":  ["E2Ycw0gJ7WnY0wQ5P8vu0ihN196K9vuiBomq62KKWo6I"],
  "bt": "0", 
  "br": [], 
  "ba": [], 
  "c": [], 
  "a": [],
  "x":  "3jrsb83XmMsQgj188ehlQ1RJLQjCcxU6_zZI8CQ8X3YcUYDbXLPtnpscwKS0KVj2KDvX06bNYIyrZxNr9Ek7pA"
}
```

- **Two-key staircase.** At inception, [`generate_keypair_for_init(curve)`](https://github.com/auths-dev/auths/blob/main/crates/auths-id/src/keri/inception.rs#L63) produces a current key (revealed in `k`) and a next key (committed only as the hash in `n`). At each `rot`, the previously-committed next key is revealed in the new `k`, and a freshly-generated key's hash is committed in the new `n`. Default curve is P-256 ([`CurveType::P256`](https://github.com/auths-dev/auths/blob/main/crates/auths-crypto/src/provider.rs#L254)) for Apple Secure Enclave + mobile support; Ed25519 selectable for Radicle compatibility.
- **Keychain-resident.** Both keys live encrypted in the OS keychain via the [`KeyStorage`](https://github.com/auths-dev/auths/blob/main/crates/auths-core/src/storage/keychain.rs) trait — Secure Enclave on macOS, Secret Service on Linux, Credential Manager on Windows, encrypted file fallback elsewhere.
- **Rotation flow.** [`rotate_keri_identity`](https://github.com/auths-dev/auths/blob/main/crates/auths-id/src/identity/rotate.rs#L61) signs a `rot` with the current key, writes the new keypair, and returns [`RotationKeyInfo`](https://github.com/auths-dev/auths/blob/main/crates/auths-id/src/identity/rotate.rs#L36).
- **No recovery tier.** Single `kt: "1"`, single `nt: "1"`. No third-tier recovery key, no `cnt`/contest event type, no weighted thresholds.
- **Git-native KEL.** Two storage backends in the workspace:
  - [`GitEventLog`](https://github.com/auths-dev/auths/blob/main/crates/auths-infra-git/src/event_log.rs#L36) writes one ref per identity at `refs/keri/<prefix>/kel`.
  - [`RegistryAttestationStorage`](https://github.com/auths-dev/auths/blob/main/crates/auths-storage/src/git/adapter.rs#L89) writes all events under a single `refs/auths/registry` ref (the path used by `auths init`).
  Either way, no DB and no service required to rotate or verify. Verification walks Git objects. Idea borrowed from [Radicle's RIP](https://app.radicle.xyz/nodes/seed.radicle.xyz/rad%3Az3trNYnLWS11cJWC6BbxDs5niGo82/tree/7ec37731062226bbcb91c38d6f003520d99c451d/000X-multi-device.md).
- **Witness scaffolding only.** [`crates/auths-core/src/witness`](https://github.com/auths-dev/auths/tree/main/crates/auths-core/src/witness) exists but is not wired as a recovery participant.

### Design intent

- **Inherit KERI's pre-rotation rather than reinvent.** The pre-commitment hash means an adversary holding the current signing key alone cannot take permanent control — they need both `k[0]` *and* the as-yet-unrevealed key whose hash is `n[0]`.
- **Keep the KEL Git-native.** Rotation events are Git objects. No DB, no service required to rotate or to verify. Verifier walks the ref. Borrowed from Radicle's RIP.
- **Keep the rotation surface minimal.** Single-sig identity KEL: every rotation is one current key + one pre-committed next. Multi-sig / threshold semantics deliberately deferred to the attestation layer (see Delegation page) rather than embedded in the KEL.

### Known weaknesses

- **Loss recovery: none.** All identity key material lives on devices. Lose every device → identity is permanently lost. Documented at [`docs/guides/identity/backup-and-recovery.md`](https://github.com/auths-dev/auths/blob/main/docs/guides/identity/backup-and-recovery.md). No social-recovery quorum, no hardware backup export, no witness backstop. Acknowledged gap.
- **Compromise recovery: same race condition as KERI.** Two-tier hierarchy means if the rotation key is compromised, controller and adversary race to issue the next `rot`. Whoever wins, wins. No higher-tier recovery key to deterministically break the tie.
- **Total-compromise response: none.** If both current and pre-committed next are exposed, auths inherits KERI's "duplicity" state — divergent KEL histories with no in-band reconciliation, requires out-of-band evidence. No `cnt`/freeze mechanism.
- **Witness-quorum recovery: not built.** Witnesses participate as backers in inception/rotation events ([`WitnessConfig`](https://github.com/auths-dev/auths/blob/main/crates/auths-id/src/witness_config.rs) populates `bt` and `b`) and observe events via [`WitnessServer`](https://github.com/auths-dev/auths/blob/main/crates/auths-core/src/witness/server.rs), but they only receipt — they are not wired as a recovery-quorum participant that can authorize a `rot` when the controller's keys are gone.

### Open question for the group

Is "rarely-revealed recovery key" (kept offline, surfaced only during recovery) operationally distinct from "never-revealed" (cryptographically blinded)? Which property does kels actually claim?

---

## Comparison

Cross-cutting analysis once all three sections above are filled. Use a table per axis where it helps; bullets where it doesn't.

| Axis | bordumb (auths) | isi | rank5.syzygy (kels) |
|---|---|---|---|
| **Key-tier hierarchy** | 2-tier: current + pre-committed next ([`generate_keypair_for_init`](https://github.com/auths-dev/auths/blob/main/crates/auths-id/src/keri/inception.rs#L63)) | … | 3-tier: current, pre-committed next, pre-committed recovery |
| **Recovery from signing-key compromise** | Standard KERI rotation via [`rotate_keri_identity`](https://github.com/auths-dev/auths/blob/main/crates/auths-id/src/identity/rotate.rs); pre-rotation hash bounds the blast radius | … | `rec` |
| **Recovery from rotation-key compromise** | Race: controller and adversary compete to issue next `rot`. No higher-tier key to break the tie | … | `rec` |
| **Total-compromise response (all known keys exposed)** | None. Falls into KERI duplicity state — divergent KEL histories, no in-band freeze/contest | … | `cnt` |
| **Reconciliation of divergent histories** | Out-of-band only. Inherits KERI's duplicity model; no `cnt`/freeze event type | … | baked into merge protocol |
| **Loss recovery (all devices destroyed)** | None. Pre-committed next key is on the same device as current ([`RotationKeyInfo`](https://github.com/auths-dev/auths/blob/main/crates/auths-id/src/identity/rotate.rs)). Documented gap in [`backup-and-recovery.md`](https://github.com/auths-dev/auths/blob/main/docs/guides/identity/backup-and-recovery.md) | … | all devices? no recourse. my stance is that multiple hardware keys on distinct devices are needed to truly allow for recovery of loss, and even then, only loss to the threshold point |
| **Recovery participants required** | Just the controller. No social quorum, no witness multi-sig, no guardian set | … | what kind of recovery? loss - threshold satisfaction of devices, compromise - the compromised device |
| **Recovery state storage** | Same as KEL: Git commits on `refs/keri/<prefix>/kel` ([`GitEventLog`](https://github.com/auths-dev/auths/blob/main/crates/auths-infra-git/src/event_log.rs)). No service required to verify a recovery event | … | in the kel |
| **Curve support on recovery path** | Workspace is curve-agnostic ([`CurveType`](https://github.com/auths-dev/auths/blob/main/crates/auths-crypto/src/provider.rs) defaults P-256, Ed25519 available); rotation events sign through [`DevicePublicKey::verify`](https://github.com/auths-dev/auths/blob/main/crates/auths-verifier/src/core.rs) dispatch | … | any valid signing algorithm kels supports (P256, ML-DSA-65/87) |
| **Detection of compromise** | Out-of-band: relying parties / external observers must spot KEL forks. No in-protocol signaling | … | evident in kel (it's possible an adversary stealthily extends the kel rather than causing divergence immediately, in which case the owner will notice when either stealth events become a problem or they try to interact with the kel (because they will then cause divergence) |

Annotate disagreements directly:

> [handle] I read this differently — explanation.

---

## Convergence

### Agreed

Things we've all signed off on. Each item should be specific enough that someone reading later can verify whether their code matches it.

- *(example)* Verification path stays service-free: a third party verifying a signature must not need to reach any party-controlled service. Local storage (SQLite, Git refs, flat files) is fine; shared/hosted services are not. *(agreed: bordumb, isi, rank5.syzygy on YYYY-MM-DD)*

### Trending toward

Ideas under active discussion, leaning toward agreement but not yet locked.

- *(example)* CESR derivation codes should match the spec table verbatim across all three implementations. *(open: bordumb auditing emitter sites; rank5.syzygy confirming kels-side prefixes; isi to comment.)*

- i think we all agree on the idea that the aid should be different from the said of the inception event
  :+1:

### Productive divergence

Areas where staying different is the right call. Documented so we don't keep rehashing.

- *(example)* Recovery key tiering: kels uses three-tier (signing/rotation/recovery); auths inherits KERI's two-tier (signing/pre-rotated next). Auths may adopt three-tier later but it's not blocking interop.
