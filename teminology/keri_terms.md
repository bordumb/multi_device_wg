# Overview

Page to converge on terms.

## Concepts

**Identity**

A representation of an entity such as a human, device or company.

**Controller**

An entity that controls at least one signing key with the authority for execution (the capability to sign an interaction event), rotation (the capability to sign a rotation event) or recovery (the capability to sign a recovery event).

## Design Tenets

- signing keys with execution and rotation authority should ideally be bound and secured by hardware
- a recovery mechanism that can recover an identity in case we loose access to these signing keys
- handle divergence of a key event log so forks in a kel can be prevented or resolved

## Applications

### Multi-Device Identity

1) Create Identity
2) Recover Identity
3) Delete Identity
4) Link Device
5) Unlink Device
6) Update Device
7) Update Recovery Method

### (todo feel free to add other usecases)

## Referece Events

We should add events from KERI spec and map the key names and definitions.

### Inception Event

Below is my inception event. Note it is missing these:
 
```json
{
  "v":  "KERI10JSON00012f_",
  "t":  "icp",
  "d":  "EZRCNIzUCUvT1rtLf59o26ZTZPKJPgGX_pJHCJ9h-FRw",
  "i":  "EZRCNIzUCUvT1rtLf59o26ZTZPKJPgGX_pJHCJ9h-FRw",
  "s":  "0",
  "kt": "1",
  "k":  ["1AAIA6CVG04Gvoxo7w1BoZBkWUoxt7jW0jslg7zyQ0jcA_wR"],
  "nt": "1",
  "n":  ["EIygB9e6mf-P6QMSw_29sozWVXqWo3crcUKsnwp7XdSI"],
  "bt": "0",
  "b":  [],
  "c":  [],
  "a":  [],
  "x":  "91ngCQXRAR8pGXGZ2h4ypPO95Tu8iJzWR57RtPwc6ITucrsqtPEquCri5Hp5ut_B9N2s8mAJB98Etgi1447b1g"
}
```

| Field | Meaning |
|---|---|
| `v` | Version string + serialized byte count |
| `t` | Event type — inception |
| `d` | Self-Addressing Identifier (SAID) of this event |
| `i` | Controller AID — for inception, equals `d` |
| `s` | Sequence number, starts at 0 |
| `kt` / `k` | Signing threshold + current public keys |
| `nt` / `n` | Next-rotation threshold + commitment hashes (the keys themselves are not yet revealed) |
| `bt` / `b` | Witness threshold + witness AIDs (none here) |
| `c` | Config traits (`EO` establishment-only, etc.) |
| `a` | Anchored seals (none here) |
| `x` | Signature over the event by the current key |

> **Spec deviations:**
> - **`x` (extra, non-spec).** Holds the issuer signature in-body. Per the KERI spec, signatures are externalized as CESR attachments after the event body, never as JSON fields. A spec-conformant verifier would compute the SAID over the event including `x` and either reject the unknown field or compute a different SAID than a reference implementation produces. Same issue is documented for receipts in `crates/auths-keri/src/witness/receipt.rs:1-12` and `crates/auths-keri/docs/epics.md:1683`.
> - **`KeriSequence` width.** Internal type is `u64`; spec mandates `u128`. Not visible in this JSON (the `s: "0"` string serialization is the same up to ~10¹⁹), but a strictly-typed verifier expecting `u128` would diverge at sequences above `2⁶⁴`.
> - **Sequence serialization unverified.** Spec says `s` is a **hex** string. `"0"` and `"1"` look identical in hex and decimal — sequence 16 is the first observable case (`"10"` hex vs `"16"` decimal). Test by rotating 16+ times and inspecting `s`.

>**Not deviations, just choices:**
> - `kt: "1"` is scalar; spec also permits weight arrays (`["1/2", "1/2", "1/2"]`). Auths uses scalar by default — precludes the kels-style weighted recovery model but is spec-legal.
> - `b: []`, `c: []`, `a: []` empty — all spec-legal default values.
> **Spec-complete:** all 13 declared `icp` fields (`v, t, d, i, s, kt, k, nt, n, bt, b, c, a`) are present in the correct order. Only `x` is extra. 


### Rotation (aka: Recovery) Event


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

New fields vs `icp`:

| Field | Meaning |
|---|---|
| `p` | Prior event SAID — must equal previous event's `d` |
| `br` / `ba` | Witnesses removed / added in this rotation 


## Terms

I'm just going to write a bunch of terms down and sort it out when I'm done

**device** - a computing device with the ability to maintain custody of cryptographic material and perform cryptographic operations

**controller** - an entity that controls one or more devices, each with at least one signing key to allow for attestation to trust decisions

**identity** - an addressable concept that defines the relationship between a controller and their devices

**loss** - the loss of physical control of a device or the keys associated with it

**compromise** - the cryptographic consequence of another entity gaining custody of an entity's controlled cryptographic material

**loss-recovery protocol** - the protocol for recovering from loss

**compromise-recovery protocol** - the protocol for recovering from compromise

**policy** - an addressable concept that defines identity capabilities (perhaps scoped to device) within a system
