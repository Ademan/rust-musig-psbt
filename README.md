# Warning!

Caveat emptor! See Warning section.

# Goals

1. Provide a critical building block for my [Boomfund](boomfund.net) assurance contract project
2. Be useful to third parties as a library (after careful review)
3. Provide a rudimentary command line tool excercising library features

This repo implements the [draft bip](https://github.com/achow101/bips/tree/musig2-psbt) for signing psbts using musig.

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

This code is un-reviewed, barely tested, and cobbled together by the author as his first rust project. You have been warned!

## Known Issues

* Wildly insufficient tests
* Zero third party review
* Doesn't support taproot script spend (TODO)
* This code was hastily adapted from prior work done before the draft bip existed, bugs are expected.
* `musig-cli` is extremely crude
