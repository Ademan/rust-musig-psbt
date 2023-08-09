# Warning!

Caveat emptor! See Warning section.

# Goals

1. Provide a critical building block for my [Boomfund](boomfund.net) assurance contract project
2. Explore the desirability of using PSBTs to coordinate collaborative signing in musig
3. Explore the design space of this problem
4. Seek third party comments on design
5. Be useful to third parties (after careful review)
6. (Potentially) seek standardization in a BIP (*lots* more work to be done, in terms of documentation and process development)

# Design

Design is subject to change!

## PSBT Serialization

### Overview
- 3 proprietary Key/Value pairs
- Suggested proprietary prefix: b"musig"

### Key/Value pairs

1. Participant (pubkey)
  - Key: Index
    32 bit little endian unsigned integer
    Key so that sort will always produce a consistent arrangement of pubkeys, so long as the key is unique.
  - Value: Pubkey
    33 byte compressed public key of participant
  - Validation:
    - Complete set of participating pubkeys are required unless the protocol set up participants out-of-band
    - If present, duplicate participants are invalid
    - If present, all parties must validate they are listed as a participant
    - If present in later steps, parties should validate that the list of participants is unchanged from the expected list
    - Skipped or missing participant indices are valid
    - If present, all parties must validate that the output public key being signed for matches the aggregate public key computed by aggregating the 
      public keys in order of their index, with low indices coming before high indices
2. Nonce
  - Key: Pubkey
    Compressed public key of participant
  - Value: musig public nonce
  - Validation: None
3. Partial Signature
  - Key: Pubkey
    Compressed public key of participant
  - Value: musig partial signature
  - Validation:
    Use musig algorithm to validate that this partial signature is a valid signature over this transaction for the given participant.

### Design Notes

- Participants are not stored in a single key/value pair with an array of participant pubkeys because it is simpler to remove the key/value pair for a participant, than to read, modify, write a single key/value pair.
- Participant indices are the key to ensure a valid PSBT (containing no duplicate keys) always produces a consistent ordering of pubkeys and therefore a consistent aggregate public key
- Pubkeys are the keys for Nonce and Partial Signature key/value pairs to eliminate duplicates and to make this proposal useful when the participant list and ordering
  is communicated out of band.
  - This justification may be weak, it only really serves the case where some peers coordinated the aggregate pubkey out of band, and some are relying purely on the PSBT to communicate this. Maybe this is relevant to hardware wallets?
  - This is also the most unambiguous encoding in the author's opinion, regardless of anticipated scenarios.

### Open Questions

- Should this proposal be generalized to other multiparty computation schemes like FROST?
  - At present, the author thinks not. Generalizing would require careful thought and future proofing, significantly delaying this, which is useful as a simpler, limited approach.
- Should nonces and partial signatures be authenticated to frustrate malicious tampering?
  - When a protocol needs to identify and evict offline or malicious peers from a signing, except in the case of a central coordinator, it is possible for a malicious peer to tamper with a third party's signing data to give the impression the third party is uncooperative.
  - This is mitigated by systems like nostr in which the whole PSBT would be signed, but this approach requires all peers to retrieve all other peers' entire PSBTs.
  - Even with a signature proving a party created certain signature data, a peer could still tamper with the PSBT to make it appear as though the target peer is offline or uncooperative by simply deleting all of the signing data for that target peer before relaying the PSBT.
  - If authentication is added, signatures should also commit to the "signing session" they are participating in case of previous failed rounds, to prevent replays
  - Might be required if there is not a central coordinator
- Should the aggnonce be encodable in the PSBT as an optimization when there is a central coordinator? (KISS for now)
- Should this proposal define anything related to descriptors?
- Future proofing for signature adaptors?

# Warning

Caveat emptor!

The author declares himself insufficiently detail oriented to work effectively on a project like this, verify, don't trust. You have been warned.
This is also the author's first rust project, you have been warned again.

- It depends on an older version of `rust-secp256k1-zkp` for the moment (TODO)

## Known Issues

* Zero feedback on general concept and direction
* Wildly insufficient tests
* Zero third party review
* Doesn't support taproot script spend (TODO)
* In the rush to slap together this readme, code and documentation are almost certianly unaligned.
* `musig-cli` is not very useful at all, and won't be until PSBT v2 support lands in `rust-bitcoin`
