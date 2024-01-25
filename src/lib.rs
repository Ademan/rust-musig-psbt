mod psbt;
mod serialize;

pub use bitcoin;
pub use secp256k1_zkp;

use secp256k1_zkp::{
    PublicKey as ZkpPublicKey,
    SecretKey as ZkpSecretKey,
    schnorr::Signature as ZkpSchnorrSignature,
    XOnlyPublicKey as ZkpXOnlyPublicKey,
};

use bitcoin::secp256k1::{
    PublicKey,
    SecretKey,
    schnorr::Signature as SchnorrSignature,
    XOnlyPublicKey,
};

use bitcoin::hashes::{
    Hash,
    HashEngine,
};

use bitcoin::hashes::sha256::{
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
    OutpointsMapError,
    ParticipantIndex,
    ParticipantsAddResult,
    PsbtHelper,
    PsbtUpdater,
    SignError,
    SignatureAggregateError,
    SpendInfoAddResult,
    tweak_keyagg,
    VerifyError,
};

pub use crate::serialize::{
    DeserializeError,
    MusigPsbtInputSerializer,
    PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS,
    PSBT_IN_MUSIG2_PUB_NONCE,
    PSBT_IN_MUSIG2_PARTIAL_SIG,
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

        engine.input(hashed_tag.as_ref());
        engine.input(hashed_tag.as_ref());

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
        Sha256::from_engine(self.0).to_byte_array()
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

    use bitcoin::secp256k1::{
        PublicKey,
        Secp256k1,
        SecretKey,
    };

    use bitcoin::psbt::{
        PartiallySignedTransaction,
    };

    use secp256k1_zkp::{
        MusigSessionId,
        Secp256k1 as ZkpSecp256k1,
    };

    use std::str::{
        FromStr,
    };

    use crate::{
        PsbtHelper,
    };

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
        PartiallySignedTransaction::from_str(s).expect("valid PSBT base64")
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
        let normal_secp = Secp256k1::new();

        let mut psbt = get_test_psbt(1);

        let PartyData { privkey: privkey1, pubkey: pubkey1 } = get_test_party(4);
        let PartyData { privkey: privkey2, pubkey: pubkey2 } = get_test_party(5);

        let participating1 = psbt.get_participating_for_pk(&secp, &pubkey1)
            .expect("results");
        assert_eq!(participating1.len(), 1);

        let participating2 = psbt.get_participating_for_pk(&secp, &pubkey2)
            .expect("results");
        assert_eq!(participating2.len(), 1);

        let (idx1, ref corectx1) = participating1[0];
        let (idx2, ref corectx2) = participating2[0];

        assert_eq!(idx1, idx2);
        assert_eq!(corectx1.script_pubkey(&normal_secp), corectx2.script_pubkey(&normal_secp));

        let extra_rand = [0u8; 32];
        let session1 = MusigSessionId::assume_unique_per_nonce_gen([1u8; 32]);
        let session2 = MusigSessionId::assume_unique_per_nonce_gen([2u8; 32]);

        let signctx1 = corectx1.add_nonce(&secp, pubkey1, &mut psbt, idx1, session1, extra_rand)
            .expect("context 1 add nonce");
        let signctx2 = corectx2.add_nonce(&secp, pubkey2, &mut psbt, idx2, session2, extra_rand)
            .expect("context 2 add nonce");

        let sigaggctx1 = signctx1.sign(&secp, &privkey1, &mut psbt, idx1)
            .expect("context 1 sign success");
        let sigaggctx2 = signctx2.sign(&secp, &privkey2, &mut psbt, idx2)
            .expect("context 2 sign success");

        let mut sigaggpsbt1 = psbt.clone();
        let mut sigaggpsbt2 = psbt.clone();

        sigaggctx1.aggregate_signatures(&secp, &mut sigaggpsbt1, idx1)
            .expect("context 1 aggregate signatures");
        sigaggctx2.aggregate_signatures(&secp, &mut sigaggpsbt2, idx2)
            .expect("context 2 aggregate signatures");

        sigaggpsbt1.finalize_key_spends();
        sigaggpsbt2.finalize_key_spends();

        sigaggpsbt1.verify()
            .expect("validate transaction");

        let tx1 = sigaggpsbt1.extract_tx();
        let tx2 = sigaggpsbt2.extract_tx();

        assert_eq!(tx1, tx2);
    }
}
