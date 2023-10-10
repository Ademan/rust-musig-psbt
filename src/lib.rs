mod psbt;
mod serialize;

pub use secp256k1_zkp::{
    All as ZkpAll,
    KeyPair as ZkpKeyPair,
    Message,
    MusigAggNonce,
    MusigKeyAggCache,
    MusigPartialSignature,
    MusigPubNonce,
    ffi::MUSIG_PUBNONCE_SERIALIZED_LEN,
    MusigSecNonce,
    MusigSession,
    MusigSessionId,
    PublicKey as ZkpPublicKey,
    Secp256k1 as ZkpSecp256k1,
    SecretKey as ZkpSecretKey,
    schnorr::Signature as ZkpSchnorrSignature,
    Signing as ZkpSigning,
    Verification as ZkpVerification,
    XOnlyPublicKey as ZkpXOnlyPublicKey,
};

pub use bitcoin::secp256k1::{
    PublicKey,
    SecretKey,
    schnorr::Signature as SchnorrSignature,
    XOnlyPublicKey,
};

pub use bitcoin::psbt::{
    PartiallySignedTransaction,
};

use bitcoin_hashes::{
    Hash,
    HashEngine,
};

use bitcoin_hashes::sha256::{
    Hash as Sha256,
    HashEngine as Sha256HashEngine,
};

use std::time::{
    UNIX_EPOCH,
};

pub use crate::psbt::{
    AggregateError,
    KeyAggregateContext,
    KeyspendContext,
    KeyspendSignContext,
    KeyspendSignatureAggregationContext,
    NonceGenerateError,
    ParticipantIndex,
    PsbtInputHelper,
    SignError,
    SignatureAggregateError,
};

pub use crate::serialize::{
    SerializeError,
    DeserializeError,
};

pub trait FromZkp {
    type TargetType;

    fn from_zkp(&self) -> Self::TargetType;
}

pub trait ToZkp {
    type ZkpType;

    fn to_zkp(&self) -> Self::ZkpType;
}

impl FromZkp for ZkpXOnlyPublicKey {
    type TargetType = XOnlyPublicKey;

    fn from_zkp(&self) -> XOnlyPublicKey {
        let bytes = self.serialize();
        XOnlyPublicKey::from_slice(&bytes)
            .expect("pk should always be valid")
    }
}

impl FromZkp for ZkpSecretKey {
    type TargetType = SecretKey;

    fn from_zkp(&self) -> SecretKey {
        let bytes = self.secret_bytes();
        SecretKey::from_slice(&bytes)
            .expect("key should always be valid")
    }
}

impl FromZkp for ZkpPublicKey {
    type TargetType = PublicKey;

    fn from_zkp(&self) -> PublicKey {
        let bytes = self.serialize();
        PublicKey::from_slice(&bytes)
            .expect("pk should always be valid")
    }
}

impl FromZkp for ZkpSchnorrSignature {
    type TargetType = SchnorrSignature;

    fn from_zkp(&self) -> SchnorrSignature {
        let bytes = self.as_ref();

        // FIXME: probably need to &bytes[..]
        SchnorrSignature::from_slice(bytes)
            .expect("signature should always be valid")
    }
}

impl ToZkp for XOnlyPublicKey {
    type ZkpType = ZkpXOnlyPublicKey;

    fn to_zkp(&self) -> ZkpXOnlyPublicKey {
        let bytes = self.serialize();
        ZkpXOnlyPublicKey::from_slice(&bytes)
            .expect("pk should always be valid")
    }
}

impl ToZkp for SecretKey {
    type ZkpType = ZkpSecretKey;

    fn to_zkp(&self) -> ZkpSecretKey {
        let bytes = self.secret_bytes();
        ZkpSecretKey::from_slice(&bytes)
            .expect("key should always be valid")
    }
}

impl ToZkp for PublicKey {
    type ZkpType = ZkpPublicKey;

    fn to_zkp(&self) -> ZkpPublicKey {
        let bytes = self.serialize();
        ZkpPublicKey::from_slice(&bytes)
            .expect("pk should always be valid")
    }
}

pub struct ExtraRand(pub Sha256HashEngine);

impl ExtraRand {
    pub fn new() -> Self {
        ExtraRand(Sha256HashEngine::default())
    }

    pub fn tagged(tag: &[u8]) -> Self {
        let mut engine = Sha256HashEngine::default();
        let hashed_tag = Sha256::hash(tag);

        engine.input(&hashed_tag);
        engine.input(&hashed_tag);

        ExtraRand(engine)
    }

    pub fn nanotime(mut self) -> Self {
        // TODO: Review assumption, probably better to panic anyway than to try to be clever
        // This is generally safe from panic, only a drastically misconfigured device would have a
        // current time before the epoch.
        let elapsed_nanos = UNIX_EPOCH.elapsed()
                                      .expect("Time elapsed since unix epoch")
                                      .as_nanos();
        self.0.input(&elapsed_nanos.to_be_bytes());

        self
    }

    pub fn into_bytes(self) -> [u8; 32] {
        Sha256::from_engine(self.0).into_inner()
    }
}

#[cfg(test)]
mod tests {
    #[cfg(not(feature="test",))]
    compile_error!("Enable feature \"test\" to build and run tests. See Adjacent comments for details.");
    // Cargo doesn't currently provide a way to automatically enable features for tests, and we
    // need to enable bitcoin/bitcoinconsensus to validate transactions.
    // There is a workaround but it has some minor drawbacks, so I'm simply alerting you early to
    // this requirement.

    use bitcoin::{
        OutPoint,
        TxOut,
    };

    use bitcoin::secp256k1::{
        PublicKey,
        Secp256k1,
        SecretKey,
    };

    use bitcoin::util::psbt::{
        PartiallySignedTransaction,
    };

    use bitcoin::consensus::{
        deserialize,
    };

    use bitcoin::hashes::hex::{
        FromHex,
    };

    use std::collections::{
        btree_map::BTreeMap,
    };

    use std::str::{
        FromStr,
    };

    use crate::{
        FromZkp,
        KeyAggregateContext,
        Message,
        MusigAggNonce,
        MusigKeyAggCache,
        MusigPartialSignature,
        MusigPubNonce,
        MusigSecNonce,
        MusigSessionId,
        ParticipantIndex,
        PsbtInputHelper,
        ToZkp,
        ZkpSecp256k1,
    };

    fn outpoint_map(psbt: &PartiallySignedTransaction) -> BTreeMap<OutPoint, TxOut> {
        psbt.unsigned_tx.input
            .iter()
            .enumerate()
            .filter_map(|(i, txin)|
                if let Some(input) = psbt.inputs.get(i) {
                    if let Some(ref txout) = input.witness_utxo {
                        Some((txin.previous_output.clone(), txout.clone()))
                    } else {
                        None
                    }
                } else {
                    None
                }
            )
            .collect()
    }

    fn hex_psbt(hex: &str) -> PartiallySignedTransaction {
        let bytes: Vec<u8> = FromHex::from_hex(hex).expect("valid hex");
        deserialize::<PartiallySignedTransaction>(&bytes).expect("valid psbt")
    }

    fn hex_pubkey(hex: &str) -> PublicKey {
        PublicKey::from_str(hex).expect("valid hex pubkey")
    }

    fn hex_privkey(hex: &str) -> SecretKey {
        SecretKey::from_str(hex).expect("valid hex privkey")
    }

    struct PartyData {
        pub pubkey: PublicKey,
        pub privkey: SecretKey,
    }

    fn get_test_party(i: usize) -> PartyData {
        let secp = Secp256k1::new();

        let privkey = match i {
            1 => { hex_privkey("4dcaff8ed1975fe2cebbd7c03384902c2189a2e6de11f1bb1c9dc784e8e4d11e") },
            2 => { hex_privkey("171a1371a3fa23e4e7b647889ba5ff3532fcdf995b6ca21fc1429669d448151e") },
            3 => { hex_privkey("ae7475e8c3a387738cc2ec8027aa41f91bb6dc4c42170ef1d212923f095a0f2a") },
            _ => {
                panic!("Invalid test party index {}", i);
            }
        };

        PartyData {
            privkey,
            pubkey: privkey.public_key(&secp),
        }
    }

    fn get_test_psbt(i: usize) -> PartiallySignedTransaction {
        match i {
            1 => {
                return hex_psbt("70736274ff01005e020000000100000000000000000000000000000000000000000000000000000000000000002a00000000ffffffff013930000000000000225120e6316b5920257522f080774efdb78f41fb0d6f54ac8628e6a0d78b6883b3f5d0000000000001012b39300000000000002251201a1947c55b0aba987b95709c57ac2ee2a2200d2358fb4a5132e21da58dc696d9011720645933cfaaa72d516f188f7d1a250b926a85412ee656e507c5082c6ad49426ad0cfc056d7573696700000000002102841d69a8b80ae23a8090e6f3765540ea5efd8c287b1307c983a6e2a3a171b5250cfc056d7573696700010000002102d0a35e00b17b89f0a5385344eac5c147e0545c1c03de212796cacdb5efbc28c00000");
            },
            _ => {
                panic!("Invalid test psbt index {}", i);
            }
        }
    }

    #[test]
    fn test_deserialize_participants() {
        let psbt = get_test_psbt(1);

        let mut participants = psbt.inputs[0]
            .iter_proprietary::<ParticipantIndex, PublicKey>(&b"musig".to_vec())
            .collect::<Result<Vec<_>, _>>()
            .expect("no deserialization errors");

        participants.sort_by_key(|x| x.0);

        assert_eq!(participants[0].1, hex_pubkey("02841d69a8b80ae23a8090e6f3765540ea5efd8c287b1307c983a6e2a3a171b525"));
        assert_eq!(participants[1].1, hex_pubkey("02d0a35e00b17b89f0a5385344eac5c147e0545c1c03de212796cacdb5efbc28c0"));
    }

    #[test]
    #[cfg(feature="test",)]
    fn test_basic() {
        let secp = ZkpSecp256k1::new();

        let psbt = get_test_psbt(1);

        let PartyData { privkey: privkey1, pubkey: pubkey1 } = get_test_party(1);
        let PartyData { privkey: privkey2, pubkey: pubkey2 } = get_test_party(2);

        let prefix = b"musig".to_vec();

        let key_context1 = KeyAggregateContext::new(&secp, pubkey1.to_zkp(), prefix.clone());
        let key_context2 = KeyAggregateContext::new(&secp, pubkey2.to_zkp(), prefix.clone());

        let keyspend_context1 = key_context1.keyspend_aggregate(&psbt, 0)
            .expect("success");
        let keyspend_context2 = key_context2.keyspend_aggregate(&psbt, 0)
            .expect("success");

        let extra_rand = [0u8; 32];
        let session_1 = MusigSessionId::assume_unique_per_nonce_gen([1u8; 32]);
        let session_2 = MusigSessionId::assume_unique_per_nonce_gen([2u8; 32]);

        let mut psbt_ng_1 = psbt.clone();
        let mut psbt_ng_2 = psbt.clone();

        let sign_context_1 = keyspend_context1.add_nonce(&mut psbt_ng_1, 0, session_1, extra_rand)
            .expect("success");
        let sign_context_2 = keyspend_context2.add_nonce(&mut psbt_ng_2, 0, session_2, extra_rand)
            .expect("success");

        psbt_ng_1.combine(psbt_ng_2)
            .expect("successful combine");

        let mut psbt_combined_nonces_1 = psbt_ng_1.clone();
        let mut psbt_combined_nonces_2 = psbt_ng_1.clone();

        let sig_agg_context_1 = sign_context_1.sign(&privkey1.to_zkp(), &mut psbt_combined_nonces_1, 0)
            .expect("success");
        let sig_agg_context_2 = sign_context_2.sign(&privkey2.to_zkp(), &mut psbt_combined_nonces_2, 0)
            .expect("success");

        psbt_combined_nonces_1.combine(psbt_combined_nonces_2)
            .expect("successful combine");

        let mut psbt_signed_1 = psbt_combined_nonces_1.clone();
        let mut psbt_signed_2 = psbt_combined_nonces_1.clone();

        sig_agg_context_1.aggregate_signatures(&mut psbt_signed_1, 0)
            .expect("success");
        sig_agg_context_2.aggregate_signatures(&mut psbt_signed_2, 0)
            .expect("success");

        let outpoints = outpoint_map(&psbt_signed_1);

        let tx1 = psbt_signed_1.extract_tx();
        let tx2 = psbt_signed_2.extract_tx();

        assert_eq!(tx1, tx2);

        tx1.verify(|point: &OutPoint| {
            outpoints.get(point).map(|txout| txout.clone())
        }).expect("valid transaction");
    }

    #[test]
    fn test_error_without_combine() {
        let secp = ZkpSecp256k1::new();
        let bitcoin_secp = Secp256k1::new();

        let psbt = hex_psbt("70736274ff01005e020000000100000000000000000000000000000000000000000000000000000000000000002a00000000ffffffff013930000000000000225120e6316b5920257522f080774efdb78f41fb0d6f54ac8628e6a0d78b6883b3f5d0000000000001012b39300000000000002251201a1947c55b0aba987b95709c57ac2ee2a2200d2358fb4a5132e21da58dc696d9011720645933cfaaa72d516f188f7d1a250b926a85412ee656e507c5082c6ad49426ad0cfc056d7573696700000000002102841d69a8b80ae23a8090e6f3765540ea5efd8c287b1307c983a6e2a3a171b5250cfc056d7573696700010000002102d0a35e00b17b89f0a5385344eac5c147e0545c1c03de212796cacdb5efbc28c00000");

        let privkey1 = hex_privkey("4dcaff8ed1975fe2cebbd7c03384902c2189a2e6de11f1bb1c9dc784e8e4d11e");
        let pubkey1 = privkey1.public_key(&bitcoin_secp);
        let privkey2 = hex_privkey("171a1371a3fa23e4e7b647889ba5ff3532fcdf995b6ca21fc1429669d448151e");
        let pubkey2 = privkey2.public_key(&bitcoin_secp);

        let prefix = b"musig".to_vec();

        let key_context1 = KeyAggregateContext::new(&secp, pubkey1.to_zkp(), prefix.clone());
        let key_context2 = KeyAggregateContext::new(&secp, pubkey2.to_zkp(), prefix.clone());

        let keyspend_context1 = key_context1.keyspend_aggregate(&psbt, 0)
            .expect("success");
        let keyspend_context2 = key_context2.keyspend_aggregate(&psbt, 0)
            .expect("success");

        let extra_rand = [0u8; 32];
        let session_1 = MusigSessionId::assume_unique_per_nonce_gen([1u8; 32]);
        let session_2 = MusigSessionId::assume_unique_per_nonce_gen([2u8; 32]);

        let mut psbt_ng_1 = psbt.clone();
        let mut psbt_ng_2 = psbt.clone();

        let sign_context_1 = keyspend_context1.add_nonce(&mut psbt_ng_1, 0, session_1, extra_rand)
            .expect("success");
        let sign_context_2 = keyspend_context2.add_nonce(&mut psbt_ng_2, 0, session_2, extra_rand)
            .expect("success");

        assert!(sign_context_1.sign(&privkey1.to_zkp(), &mut psbt_ng_1, 0).is_err());
        assert!(sign_context_2.sign(&privkey2.to_zkp(), &mut psbt_ng_2, 0).is_err());
    }
}
