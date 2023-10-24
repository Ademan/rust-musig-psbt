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
    Parity as ZkpParity,
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
    CoreContextCreateError,
    CoreContext,
    SignContext,
    SignatureAggregateContext,
    NonceGenerateError,
    ParticipantIndex,
    PsbtHelper,
    PsbtUpdater,
    SignError,
    SignatureAggregateError,
    SpendInfoAddResult,
    tweak_keyagg,
};

pub use crate::serialize::{
    DeserializeError,
    MusigPsbtInputSerializer,
    PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS,
    PSBT_IN_MUSIG2_PUB_NONCE,
    PSBT_IN_MUSIG_PARTIAL_SIG,
    SerializeError,
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

    use base64::{
        engine::general_purpose::STANDARD,
        read::DecoderReader as Base64Reader,
        write::EncoderWriter as Base64Writer,
    };

    use bitcoin::{
        OutPoint,
        TxOut,
    };

    use bitcoin::consensus::encode::{
        Decodable,
        Encodable,
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
        MusigSessionId,
        ToZkp,
        ZkpSecp256k1,
        PsbtHelper,
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

    fn b64_psbt(s: &str) -> PartiallySignedTransaction {
        let mut reader = Base64Reader::new(s.as_bytes(), &STANDARD);

        PartiallySignedTransaction::consensus_decode_from_finite_reader(&mut reader).expect("valid PSBT base64")
    }

    fn get_test_psbt(i: usize) -> PartiallySignedTransaction {
        match i {
            0 => {
                return b64_psbt("cHNidP8BAFICAAAAAd0n6Ue88GoAyvS3s+K5S2stL3BwdVf+dwGGq1xRyi2HAAAAAAD9////ATyGAQAAAAAAFgAUIgoB0Q5jlXI3vIWjadirvITSd7QAAAAAAAEBK6CGAQAAAAAAIlEgcX50Lq8jZsQjpqvJKD7qBIgBU+B+NOE6ShDTptsR2lwAIgICMEGVnLA5ohZx859OOSXQGHUUsvvqPQ47HSKpI6+nBfkYG9JvMFQAAIABAACAAAAAgAAAAAANAAAAAA==");
            },
            1 => {
                return b64_psbt("cHNidP8BAFICAAAAAd0n6Ue88GoAyvS3s+K5S2stL3BwdVf+dwGGq1xRyi2HAAAAAAD9////ATyGAQAAAAAAFgAUIgoB0Q5jlXI3vIWjadirvITSd7QAAAAAAAEBK6CGAQAAAAAAIlEgcX50Lq8jZsQjpqvJKD7qBIgBU+B+NOE6ShDTptsR2lwBFyBn3Wj/ueWc19QEdQHevj2Mz+p7VeaU0NX/uw6GruGA9gAiAgIwQZWcsDmiFnHzn045JdAYdRSy++o9DjsdIqkjr6cF+Rgb0m8wVAAAgAEAAIAAAACAAAAAAA0AAAAA");
            },
            _ => {
                panic!("Invalid test psbt index {}", i);
            }
        }
    }

    #[test]
    #[cfg(feature="test",)]
    fn test_basic() {
        let secp = ZkpSecp256k1::new();

        let mut psbt = get_test_psbt(1);

        let PartyData { privkey: privkey1, pubkey: pubkey1 } = get_test_party(1);
        let PartyData { privkey: privkey2, pubkey: pubkey2 } = get_test_party(2);

        let participating1 = psbt.get_participating_for_pk(&secp, &pubkey1).expect("results");
        assert!(participating1.len() == 1);

        let participating2 = psbt.get_participating_for_pk(&secp, &pubkey2).expect("results");
        assert!(participating2.len() == 1);

        let (ridx1, corectx1) = &participating1[0];
        let (ridx2, corectx2) = &participating2[0];

        // XXX: there's got to be a better way
        // Should be able to deref in destructuring... right?
        let (idx1, idx2) = (*ridx1, *ridx2);

        let extra_rand = [0u8; 32];
        let session1 = MusigSessionId::assume_unique_per_nonce_gen([1u8; 32]);
        let session2 = MusigSessionId::assume_unique_per_nonce_gen([2u8; 32]);

        let signctx1 = corectx1.add_nonce(&secp, pubkey1, &mut psbt, idx1, session1, extra_rand).expect("success");
        let signctx2 = corectx2.add_nonce(&secp, pubkey2, &mut psbt, idx2, session2, extra_rand).expect("success");

        let sigaggctx1 = signctx1.sign(&secp, &privkey1, &mut psbt, idx1)
            .expect("sign success");
        let sigaggctx2 = signctx2.sign(&secp, &privkey2, &mut psbt, idx2)
            .expect("sign success");

        let mut sigaggpsbt1 = psbt.clone();
        let mut sigaggpsbt2 = psbt.clone();

        sigaggctx1.aggregate_signatures(&secp, &mut sigaggpsbt1, idx1)
            .expect("success");
        sigaggctx2.aggregate_signatures(&secp, &mut sigaggpsbt2, idx2)
            .expect("success");

        let outpoints = outpoint_map(&sigaggpsbt1);

        let tx1 = sigaggpsbt1.extract_tx();
        let tx2 = sigaggpsbt2.extract_tx();

        assert_eq!(tx1, tx2);

        tx1.verify(|point: &OutPoint| {
            outpoints.get(point).map(|txout| txout.clone())
        }).expect("valid transaction");
    }
}
