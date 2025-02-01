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

use std::time::UNIX_EPOCH;

pub use crate::psbt::{
    CoreContextCreateError,
    CoreContext,
    FindParticipatingExtendedKeys,
    FindParticipatingKeys,
    musig_agg_pk_to_xpub,
    NonceGenerateError,
    OutpointsMapError,
    ParticipantsAddResult,
    PsbtHelper,
    PsbtUpdater,
    SignatureAggregateContext,
    SignatureAggregateError,
    SignContext,
    SignError,
    SpendInfoAddResult,
    TaprootScriptPubkey,
    taproot_sighash,
    VerifyError,
};

pub use crate::serialize::{
    DeserializeError,
    MusigPsbtInputSerializer,
    MusigPsbtInputs,
    MusigPsbtInput,
    ParticipantIndex,
    SerializeError,
    SerializeOrDeserializeError,
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
    use bitcoin::{
        Psbt,
    };

    use bitcoin::secp256k1::{
        PublicKey,
        Secp256k1,
        SecretKey,
    };

    use secp256k1_zkp::{
        MusigSessionId,
        Secp256k1 as ZkpSecp256k1,
    };

    use std::iter::{
        FromIterator,
        once,
    };

    use std::str::FromStr;

    use crate::{
        CoreContext,
        PsbtHelper,
        MusigPsbtInputs,
        MusigPsbtInput,
        FindParticipatingKeys,
        taproot_sighash,
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

    fn get_test_psbt(i: usize) -> Psbt {
        match i {
            1 => {
                return Psbt::from_str("cHNidP8BAIkCAAAAAXhVYaAW/V44yVXrxatXaQ6n/200MkqLY11ChcilXzT+AAAAAAD9////AgDh9QUAAAAAIlEgZ91o/7nlnNfUBHUB3r49jM/qe1XmlNDV/7sOhq7hgPZlEBAkAQAAACJRIGfdaP+55ZzX1AR1Ad6+PYzP6ntV5pTQ1f+7Doau4YD2AAAAAE8BBDWHzwAAAAAAAAAAAA1AItJh9Nhh7/N92XW3W2vMfit2gCOOO1j/6HKuwbgvA63PIu31XxCfhL/etap2KRiSMCOEOUUG9f5u5StDYJXIBMBhd8wAAQErAPIFKgEAAAAiUSBn3Wj/ueWc19QEdQHevj2Mz+p7VeaU0NX/uw6GruGA9iEWVSEt/3s9foEmaHpi/QQ1o/tN5W2a+a4jocnKBbNJyOIZAMBhd8xWAACAAQAAgAAAAIAFAAAAAAAAACEWzlfSl11hJNfyGblg0/aQ1c6LKqm0cct9V8VP70WUwukFAAbYZgchFtZEsba0rVY3RLO1NPryqBMu9Np3coiJLCYMxXpkT+Z2GQDAYXfMVgAAgAEAAIAAAACABAAAAAAAAAABFyDOV9KXXWEk1/IZuWDT9pDVzosqqbRxy31XxU/vRZTC6SIaA85X0pddYSTX8hm5YNP2kNXOiyqptHHLfVfFT+9FlMLpQgPWRLG2tK1WN0SztTT68qgTLvTad3KIiSwmDMV6ZE/mdgNVIS3/ez1+gSZoemL9BDWj+03lbZr5riOhycoFs0nI4gABBSDOV9KXXWEk1/IZuWDT9pDVzosqqbRxy31XxU/vRZTC6SEHzlfSl11hJNfyGblg0/aQ1c6LKqm0cct9V8VP70WUwukFAAbYZgcAAQUgzlfSl11hJNfyGblg0/aQ1c6LKqm0cct9V8VP70WUwukhB85X0pddYSTX8hm5YNP2kNXOiyqptHHLfVfFT+9FlMLpBQAG2GYHAA==").unwrap();
            },
            _ => {
                panic!("Invalid test psbt index {}", i);
            }
        }
    }

    #[test]
    fn test_basic() {
        let secp = ZkpSecp256k1::new();
        let normal_secp = Secp256k1::new();

        let mut psbt = get_test_psbt(1);

        let PartyData { privkey: privkey1, pubkey: pubkey1 } = get_test_party(4);
        let PartyData { privkey: privkey2, pubkey: pubkey2 } = get_test_party(5);

        let musig_inputs = MusigPsbtInputs::from_psbt(&psbt).unwrap();

        let participating1 = FindParticipatingKeys::from_iter(once(pubkey1.clone()));
        let participating1: Vec<CoreContext> = participating1.iter_participating_context(&normal_secp, &secp, &psbt, &musig_inputs)
            .map(|(_input_index, arg)| {
                let (pk, context) = arg.expect("valid context");
                assert_eq!(pk, pubkey1);
                context
            })
            .collect();

        assert_eq!(participating1.len(), 1);

        let participating2 = FindParticipatingKeys::from_iter(once(pubkey2.clone()));
        let participating2: Vec<CoreContext> = participating2.iter_participating_context(&normal_secp, &secp, &psbt, &musig_inputs)
            .map(|(_input_index, arg)| {
                let (pk, context) = arg.expect("valid context");
                assert_eq!(pk, pubkey2);
                context
            })
            .collect();
        assert_eq!(participating2.len(), 1);

        // FIXME: add iter_participating to entire PSBT to be compatible with this format
        let (idx1, ref corectx1) = (0, &participating1[0]);
        let (idx2, ref corectx2) = (0, &participating2[0]);

        assert_eq!(idx1, idx2);
        assert_eq!(corectx1.xonly_public_key(), corectx2.xonly_public_key());

        let extra_rand = [0u8; 32];
        let session1 = MusigSessionId::assume_unique_per_nonce_gen([1u8; 32]);
        let session2 = MusigSessionId::assume_unique_per_nonce_gen([2u8; 32]);

        let sighash1 = taproot_sighash(&psbt, idx1, corectx1.tap_leaf)
            .expect("sighash");
        let sighash2 = taproot_sighash(&psbt, idx2, corectx2.tap_leaf)
            .expect("sighash");

        assert_eq!(sighash1, sighash2);

        let mut musig_input = MusigPsbtInput::from_input(&psbt.inputs[idx1])
            .expect("psbt input");

        let signctx1 = corectx1.add_nonce(&secp, pubkey1, &mut musig_input, &sighash1, session1, extra_rand)
            .expect("context 1 add nonce");
        let signctx2 = corectx2.add_nonce(&secp, pubkey2, &mut musig_input, &sighash2, session2, extra_rand)
            .expect("context 2 add nonce");

        let sigaggctx1 = signctx1.sign(&secp, &privkey1, &mut musig_input, &sighash1)
            .expect("context 1 sign success");
        let sigaggctx2 = signctx2.sign(&secp, &privkey2, &mut musig_input, &sighash1)
            .expect("context 2 sign success");

        sigaggctx1.aggregate_signatures(&secp, &mut psbt.inputs[idx1], &musig_input)
            .expect("context 1 aggregate signatures");
        sigaggctx2.aggregate_signatures(&secp, &mut psbt.inputs[idx1], &musig_input)
            .expect("context 2 aggregate signatures");

        psbt.finalize_key_spends();

        psbt.verify()
            .expect("validate transaction");
    }
}
