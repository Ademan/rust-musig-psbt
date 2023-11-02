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
    ParticipantsAddResult,
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

/// Trait for converting from libsecp256k1-zkp types to libsecp256k1 types
pub trait FromZkp {
    type TargetType;

    fn from_zkp(&self) -> Self::TargetType;
}

/// Trait for converting from libsecp256k1 types to libsecp256k1-zkp types
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

/// Help generate a useful extra "random" value to increase entropy
pub struct ExtraRand(pub Sha256HashEngine);

impl ExtraRand {
    pub fn new() -> Self {
        ExtraRand(Sha256HashEngine::default())
    }

    /// Initialize a tagged ExtraRand object
    pub fn tagged(tag: &[u8]) -> Self {
        let mut engine = Sha256HashEngine::default();
        let hashed_tag = Sha256::hash(tag);

        engine.input(&hashed_tag);
        engine.input(&hashed_tag);

        ExtraRand(engine)
    }

    /// Add number of nanoseconds since the epoch to the hashed value
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

    /// Retrieve extra rand bytes suitable to pass to CoreContext::generate_nonce() and CoreContext::add_nonce()
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
    };

    use bitcoin::{
        OutPoint,
        TxOut,
    };

    use bitcoin::consensus::encode::{
        Decodable,
    };

    use bitcoin::secp256k1::{
        PublicKey,
        Secp256k1,
        SecretKey,
    };

    use bitcoin::util::psbt::{
        PartiallySignedTransaction,
    };

    use std::collections::{
        btree_map::BTreeMap,
    };

    use std::str::{
        FromStr,
    };

    use crate::{
        MusigSessionId,
        ZkpSecp256k1,
        PsbtHelper,
    };

    fn outpoint_map(psbt: &PartiallySignedTransaction) -> BTreeMap<OutPoint, TxOut> {
        psbt.unsigned_tx.input
            .iter()
            .enumerate()
            .filter_map(|(i, txin)| {
                let input = psbt.inputs.get(i)?;
                let txout = input.witness_utxo.as_ref()?;
                Some((txin.previous_output.clone(), txout.clone()))
            })
            .collect()
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

        // I'd rather keep these keys hard coded for the test but they are derived as follows:
        // tprv8ZgxMBicQKsPd1EzCPZcQSPhsotX5HvRDCivA7ASNQFmjWuTsW3WWEwUNKFAZrnD9qpz55rtyLdphqkwRZUqNWYXwSEzd6P4pYvXGByRim3/86'/1'/0'/i/0

        let privkey = match i {
            0 => { hex_privkey("4dcaff8ed1975fe2cebbd7c03384902c2189a2e6de11f1bb1c9dc784e8e4d11e") },
            1 => { hex_privkey("171a1371a3fa23e4e7b647889ba5ff3532fcdf995b6ca21fc1429669d448151e") },
            2 => { hex_privkey("02ed58011a5ab8fb93516bc66f7c57c0939c18d0137f3438ceee8fb9944bfbc0") },
            3 => { hex_privkey("ae7475e8c3a387738cc2ec8027aa41f91bb6dc4c42170ef1d212923f095a0f2a") },
            4 => { hex_privkey("71979b1aaee2900ca7aafe22bfc7beab263c9b6a31363157939b47d6b4c86b9e") },
            5 => { hex_privkey("ad9938c3f23e4273391057cd079088bfff593a91a0d628951218baeee9511592") },
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
                return b64_psbt("cHNidP8BAFICAAAAAd0n6Ue88GoAyvS3s+K5S2stL3BwdVf+dwGGq1xRyi2HAAAAAAD9////ATyGAQAAAAAAFgAUIgoB0Q5jlXI3vIWjadirvITSd7QAAAAAAAEBK6CGAQAAAAAAIlEgcX50Lq8jZsQjpqvJKD7qBIgBU+B+NOE6ShDTptsR2lwBFyBn3Wj/ueWc19QEdQHevj2Mz+p7VeaU0NX/uw6GruGA9iEZZ91o/7nlnNfUBHUB3r49jM/qe1XmlNDV/7sOhq7hgPZCA9ZEsba0rVY3RLO1NPryqBMu9Np3coiJLCYMxXpkT+Z2A1UhLf97PX6BJmh6Yv0ENaP7TeVtmvmuI6HJygWzScjiACICAjBBlZywOaIWcfOfTjkl0Bh1FLL76j0OOx0iqSOvpwX5GBvSbzBUAACAAQAAgAAAAIAAAAAADQAAAAA=");
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

        let PartyData { privkey: privkey1, pubkey: pubkey1 } = get_test_party(4);
        let PartyData { privkey: privkey2, pubkey: pubkey2 } = get_test_party(5);

        let participating1 = psbt.get_participating_for_pk(&secp, &pubkey1).expect("results");
        assert_eq!(participating1.len(), 1);

        let participating2 = psbt.get_participating_for_pk(&secp, &pubkey2).expect("results");
        assert_eq!(participating2.len(), 1);

        let (idx1, ref corectx1) = participating1[0];
        let (idx2, ref corectx2) = participating2[0];

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
