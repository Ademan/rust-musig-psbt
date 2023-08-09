PSBT Serialization

- 3 key/value pairs
- Suggested proprietary prefix: b"musig"

1. Participant (pubkey)
  - Key: Index
    32 bit little endian unsigned integer
    Key so that sort will always produce a consistent arrangement of pubkeys, so long as the key is unique.
  - Value: Pubkey
    Compressed public key of participant
  - Validation:
    - Participants are required unless the protocol set up participants out-of-band
    - If present, duplicate participants are invalid
    - If present, all parties must validate they are listed as a participant
    - If present in later steps, parties should validate that the list of participants is unchanged from the expected list
    - Skipped or missing indices are valid
    - If present, all parties must validate that the output public key being signed for matches the aggregate public key computed by aggregating the 
      public keys in order of their index, with low indices coming before high indices
2. Nonce
  - Key: Pubkey
    Compressed public key of participant
  - Value: public nonce
  - Validation: None
3. Partial Signature
  - Key: Pubkey
    Compressed public key of participant
  - Value: partial signature
  - Validation:
    Use musig algorithm to validate that this partial signature is a valid signature over this transaction for the given participant.
