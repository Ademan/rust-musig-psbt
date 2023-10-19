# Warning!

Caveat emptor! See Warning section.

# Goals

1. Provide a critical building block for my [Boomfund](boomfund.net) assurance contract project
2. ~~Explore the desirability of using PSBTs to coordinate collaborative signing in musig~~ The existence of a [draft bip](https://github.com/achow101/bips/tree/musig2-psbt) suggests it is desirable.
3. ~~Explore the design space of this problem~~ The draft bip is very similar to this proposal in the keyspend case, however this proposal does not address script spends, making the bip a superset.
4. ~~Seek third party comments on design~~ The draft bip will attract the necessary comments.
5. Be useful to third parties (after careful review)
6. ~~(Potentially) seek standardization in a BIP (*lots* more work to be done, in terms of documentation and process development)~~ The author of this proposal is satisfied the draft bip is superior to this proposal.

This repo is intended to implement the [draft bip](https://github.com/achow101/bips/tree/musig2-psbt).

### Open Questions

- Should nonces and partial signatures be authenticated to frustrate malicious tampering?
  - When a protocol needs to identify and evict offline or malicious peers from a signing, except in the case of a central coordinator, it is possible for a malicious peer to tamper with a third party's signing data to give the impression the third party is uncooperative.
  - This is mitigated by systems like nostr in which the whole PSBT would be signed, but this approach requires all peers to retrieve all other peers' entire PSBTs.
  - Even with a signature proving a party created certain signature data, a peer could still tamper with the PSBT to make it appear as though the target peer is offline or uncooperative by simply deleting all of the signing data for that target peer before relaying the PSBT.
  - If authentication is added, signatures should also commit to the "signing session" they are participating in case of previous failed rounds, to prevent replays
  - Might be required if there is not a central coordinator
- Should the aggnonce be encodable in the PSBT as an optimization when there is a central coordinator? (KISS for now)
- Future proofing for signature adaptors?

# Warning

Caveat emptor!

The author declares himself insufficiently detail oriented to work effectively on a project like this, verify, don't trust. You have been warned.
This is also the author's first rust project, you have been warned again.

- It depends on an older version of `rust-secp256k1-zkp` for the moment (TODO)

## Known Issues

* Wildly insufficient tests
* Zero third party review
* Doesn't support taproot script spend (TODO)
* In the rush to slap together this readme, code and the draft bip are almost certianly unaligned.
* `musig-cli` is not very useful at all, and won't be until PSBT v2 support lands in `rust-bitcoin`
* Validation needs to be stepped back up
