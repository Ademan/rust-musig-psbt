use bitcoin::{
    SchnorrSighashType,
    Script,
    TxOut,
};

use bitcoin::psbt::{
    Input as PsbtInput,
    raw::ProprietaryType,
    PsbtSighashType,
};

use bitcoin::secp256k1::{
    PublicKey,
    Signing,
    Secp256k1,
    Verification,
};

use bitcoin::util::sighash::{
    Prevouts,
    SighashCache,
};

use bitcoin::util::schnorr::{
    SchnorrSig,
};

use bitcoin::util::taproot::{
    TapBranchHash,
    TapSighashHash,
    TapTweakHash,
};

use bitcoin_hashes::{
    Hash,
};

use crate::{
    FromZkp,
    Message,
    MusigAggNonce,
    MusigKeyAggCache,
    MusigPartialSignature,
    MusigPubNonce,
    MusigSecNonce,
    MusigSession,
    MusigSessionId,
    PartiallySignedTransaction,
    ToZkp,
    ZkpKeyPair,
    ZkpPublicKey,
    ZkpSchnorrSignature,
    ZkpSecp256k1,
    ZkpSecretKey,
    ZkpSigning,
    ZkpVerification,
    ZkpXOnlyPublicKey,
};

use crate::serialize::{
    ProprietaryKeyIterator,
    ProprietaryKeyConvertible,
    PsbtValue,
    ToPsbtKeyValue,
};

use std::collections::{
    btree_map::BTreeMap,
    btree_set::BTreeSet,
};

use std::fmt::{
    Display,
    Error as FmtError,
    Formatter,
};

/// The type of the index of a participant in an aggregate signing
pub type ParticipantIndex = u32;

/// The type of the proprietary prefix
pub type ProprietaryPrefix = Vec<u8>;

/// An error when generating the sighash when signing for a taproot
/// input
#[derive(Debug)]
pub enum SighashError {
    InvalidInputIndexError,
    IncompatibleSighashError(PsbtSighashType),
    UnimplementedSighashError(SchnorrSighashType),
    MissingPrevoutError(usize),
    SighashError,
}

impl Display for SighashError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), FmtError> {
        match self {
            &SighashError::InvalidInputIndexError => {
                write!(f, "Invalid input index")
            },
            &SighashError::IncompatibleSighashError(sighash_type) => {
                write!(f, "Incompatible Sighash {}", sighash_type)
            },
            &SighashError::UnimplementedSighashError(sighash_type) => {
                write!(f, "Unimplemented Sighash {}", sighash_type)
            },
            &SighashError::MissingPrevoutError(i) => {
                write!(f, "Missing prevout for input at {}", i)
            },
            &SighashError::SighashError => {
                write!(f, "Sighash error")
            },
        }
    }
}

#[derive(Debug)]
pub enum TweakError {
    TweakError,
}

pub fn tweak_keyagg<C: ZkpVerification>(secp: &ZkpSecp256k1<C>, keyagg_cache: &mut MusigKeyAggCache, merkle_root: Option<TapBranchHash>) -> Result<(ZkpXOnlyPublicKey, ZkpXOnlyPublicKey), TweakError> {
    let inner_pk = keyagg_cache.agg_pk();

    let tweak = TapTweakHash::from_key_and_tweak(inner_pk.from_zkp(), merkle_root);

    let tweak_key = ZkpSecretKey::from_slice(tweak.as_inner())
        .map_err(|_| TweakError::TweakError)?; // tweak is not a valid private key

    let tweaked_pk = keyagg_cache.pubkey_xonly_tweak_add(secp, tweak_key)
        .map_err(|_| TweakError::TweakError)?; // tweak negates agg pk

    Ok((inner_pk, tweaked_pk))
}

/// Generate the sighash to sign for a taproot input
pub fn taproot_keyspend_sighash(psbt: &PartiallySignedTransaction, input_index: usize) -> Result<TapSighashHash, SighashError> {
    let psbt_input = psbt.inputs.get(input_index)
        .ok_or(SighashError::InvalidInputIndexError)?;

    let sighash_type = psbt_input.sighash_type
        .unwrap_or(SchnorrSighashType::Default.into());

    let psbt_sighash = sighash_type.schnorr_hash_ty()
        .map_err(|_| SighashError::IncompatibleSighashError(sighash_type))?;

    let mut txouts: Vec<&TxOut>;
    let prevouts: Prevouts<_> = match psbt_sighash {
        SchnorrSighashType::None | SchnorrSighashType::NonePlusAnyoneCanPay => {
            return Err(SighashError::UnimplementedSighashError(psbt_sighash));
        },
        SchnorrSighashType::Default | SchnorrSighashType::All | SchnorrSighashType::Single => {
            let fallible_txouts: Result<Vec<&TxOut>, _> = psbt.inputs.iter()
                .enumerate()
                .map(|(i, input)| match &input.witness_utxo {
                    &None => Err(SighashError::MissingPrevoutError(i)),
                    &Some(ref prevout) => Ok(prevout),
                }).collect();

            txouts = fallible_txouts?;
            Prevouts::All(&txouts[..])
        },
        SchnorrSighashType::AllPlusAnyoneCanPay | SchnorrSighashType::SinglePlusAnyoneCanPay => {
            let utxo = psbt_input.witness_utxo
                .as_ref()
                .ok_or(SighashError::MissingPrevoutError(input_index))?;

            Prevouts::One(input_index, utxo)
        },
    };

    let mut cache = SighashCache::new(&psbt.unsigned_tx);

    cache
        .taproot_key_spend_signature_hash(input_index, &prevouts, psbt_sighash)
        .map_err(|_| SighashError::SighashError)
}

/// Initial context for aggregating keys
pub struct KeyAggregateContext<'a, C: ZkpVerification + ZkpSigning> {
    secp: &'a ZkpSecp256k1<C>,
    prefix: Vec<u8>,
    pubkey: ZkpPublicKey,
}

#[derive(Debug)]
pub enum AggregateError {
    NoParticipantsError,
    NotAParticipantError,
    // XXX: What if there's only our pubkey? Some kind of attack?
    //OneParticipant,
    // XXX: Add input details?
    MissingInnerPubkey,
    MalformedInputError,
    NotAKeyspendError,
    AggregateError,
    AggregateKeyMismatch,
    DuplicateParticipantError,
    InvalidTweakError,
    InvalidInputIndexError,
    PlaceholderError,
}

pub enum PsbtNormalizeAction {
    NoAction,
    InternalKeyAdded,
}

pub enum PsbtNormalizeError {
    PsbtNormalizeError,
    InternalKeyAddError(InternalKeyAddError),
    InvalidInputIndexError,
}

pub enum InternalKeyAddError {
    MissingInnerPubkey,
    InternalKeyAddError,
    InvalidInputIndexError,
}

pub enum ParticipantsRepairError {
    InvalidInputIndexError,
}

pub struct CoreContext {
    participants: InputParticipants,
    keyagg_cache: MusigKeyAggCache,
    inner_agg_pk: ZkpXOnlyPublicKey,
    merkle_root: Option<TapBranchHash>,
}

#[derive(Debug)]
pub enum CoreContextCreateError {
    TweakError,
}

impl CoreContext {
    pub fn new<C: ZkpVerification>(secp: &ZkpSecp256k1<C>, participant_pubkeys: Vec<PublicKey>) -> Result<Self, CoreContextCreateError> {
        let participants = InputParticipants::from_participant_pubkeys(participant_pubkeys);

        let mut keyagg_cache = participants.to_keyagg_cache(secp);

        let merkle_root = None;
        let (inner_agg_pk, _) = tweak_keyagg(secp, &mut keyagg_cache, merkle_root)
            .map_err(|_| CoreContextCreateError::TweakError)?;

        Ok(CoreContext {
            participants,
            keyagg_cache,
            inner_agg_pk,
            merkle_root,
        })
    }

    pub fn updater<'a, C: ZkpSigning>(&'a self, secp: &'a ZkpSecp256k1<C>) -> Updater<'a, C> {
        Updater {
            secp,
            participants: &self.participants,
            keyagg_cache: &self.keyagg_cache,
            inner_agg_pk: self.inner_agg_pk,
            tap_leaf: None, // FIXME
            merkle_root: self.merkle_root,
        }
    }
}

pub struct Updater<'a, C: ZkpSigning> {
    secp: &'a ZkpSecp256k1<C>,
    participants: &'a InputParticipants,
    keyagg_cache: &'a MusigKeyAggCache,
    inner_agg_pk: ZkpXOnlyPublicKey,
    tap_leaf: Option<TapBranchHash>,
    merkle_root: Option<TapBranchHash>,
}

impl<'a, C: ZkpVerification + ZkpSigning> From<&'a KeyspendContext<'a, C>> for Updater<'a, C> {
    fn from(context: &'a KeyspendContext<'a, C>) -> Self {
        context.updater()
    }
}

#[derive(Debug)]
pub enum SpendInfoAddResult {
    InputNoMatch, // XXX: Should this be an error?
    Success {
        internal_key_modified: bool,
        merkle_root_modified: bool,
    },
}

#[derive(Debug)]
pub enum SpendInfoAddError {
    WitnessUtxoMissing,
}

impl<'a, C: ZkpSigning> Updater<'a, C> {
    pub fn add_spend_info<C2: Verification>(&self, secp: &Secp256k1<C2>, input: &mut PsbtInput) -> Result<SpendInfoAddResult, SpendInfoAddError> {
        let script = Script::new_v1_p2tr(secp,
                                         self.inner_agg_pk.from_zkp(),
                                         self.merkle_root);

        let utxo = input.witness_utxo
            .as_ref()
            .ok_or(SpendInfoAddError::WitnessUtxoMissing)?;

        if utxo.script_pubkey.clone() != script.clone() {
            return Ok(SpendInfoAddResult::InputNoMatch);
        }

        let mut internal_key_modified = false;
        let mut merkle_root_modified = false;

        let tap_internal_key = Some(self.inner_agg_pk.from_zkp());

        if input.tap_internal_key != tap_internal_key {
            input.tap_internal_key = tap_internal_key;
            internal_key_modified = true;
        }

        if input.tap_merkle_root != self.merkle_root {
            input.tap_merkle_root = self.merkle_root;
            merkle_root_modified = true;
        }

        Ok(SpendInfoAddResult::Success {
            internal_key_modified,
            merkle_root_modified,
        })
    }

    pub fn fix_participants(&self, input: &mut PsbtInput) -> bool {
        unimplemented!();
    }
}

impl<'a, C: ZkpVerification + ZkpSigning> KeyAggregateContext<'a, C> {
    pub fn new(secp: &'a ZkpSecp256k1<C>, pubkey: ZkpPublicKey, prefix: Vec<u8>) -> Self {
        KeyAggregateContext {
            secp,
            prefix,
            pubkey,
        }
    }

    /// Aggregate pubkeys from a psbt input in preparation for signing
    pub fn keyspend_aggregate(&'a self, psbt: &PartiallySignedTransaction, input_index: usize) -> Result<KeyspendContext<'a, C>, AggregateError> {
        let input = psbt.inputs
            .get(input_index)
            .ok_or(AggregateError::InvalidInputIndexError)?;

        let psbt_inner_pk = input.tap_internal_key
            .ok_or(AggregateError::MissingInnerPubkey)?;

        let participants = InputParticipants::from_input_keyspend(input, &self.prefix)
            .map_err(|e|
                match e {
                    ParticipantError::NoParticipantsError => {
                        AggregateError::NoParticipantsError
                    },
                    ParticipantError::DuplicateParticipantError => {
                        AggregateError::DuplicateParticipantError
                    },
                    ParticipantError::DeserializeError => {
                        AggregateError::MalformedInputError
                    },
                }
            )?;

        let selfpubkey = self.pubkey.from_zkp();
        // XXX: Confused by the double reference here, doesn't it return Iterator<Item = &PublicKey> ?
        // Oh it does, but find gives us a reference to Item, not Item (makes sense) should participants.iter() return Iterator<PublicKey> then?
        // Would that be stupid? Not sure if that implies excessive copies
        participants.iter()
            .find(|&&pk| pk == selfpubkey)
            .ok_or(AggregateError::NotAParticipantError)?;

        let mut keyagg_cache = participants.to_keyagg_cache(&self.secp);
        let (inner_agg_pk, _) = tweak_keyagg(&self.secp, &mut keyagg_cache, input.tap_merkle_root)
            .map_err(|_| AggregateError::InvalidTweakError)?;

        if inner_agg_pk.from_zkp() != psbt_inner_pk {
            return Err(AggregateError::AggregateKeyMismatch);
        }

        Ok(KeyspendContext {
            secp: self.secp,
            prefix: self.prefix.to_owned(),
            pubkey: self.pubkey,
            participants,
            absent_participants_valid: false,
            keyagg_cache,
            inner_agg_pk,
        })
    }
}

#[derive(Clone,PartialEq)]
struct InputParticipants {
    participants: Vec<PublicKey>,
}

pub enum ParticipantError {
    NoParticipantsError,
    DuplicateParticipantError,
    DeserializeError,
}

pub enum ParticipantMatchError {
    DeserializeError,
    ParticipantMatchError,
    NoParticipantsError,
}

impl InputParticipants {
    pub fn from_participant_pubkeys(participants: Vec<PublicKey>) -> Self {
        Self { participants }
    }

    pub fn from_input_keyspend(input: &PsbtInput, proprietary_prefix: &Vec<u8>) -> Result<Self, ParticipantError> {
        let iter = input.iter_proprietary::<ParticipantIndex, PublicKey>(proprietary_prefix);

        let mut key_participants = iter
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| ParticipantError::DeserializeError)?;
        key_participants.sort_by_key(|x| x.0);

        if key_participants.is_empty() {
            return Err(ParticipantError::NoParticipantsError);
        }

        let mut seen_keys: BTreeSet<PublicKey> = BTreeSet::new();
        for (_i, key) in key_participants.iter() {
            if !seen_keys.insert(*key) {
                return Err(ParticipantError::DuplicateParticipantError);
            }
        }

        Ok(Self {
            participants: key_participants
                .iter()
                .map(|&(_i, key)| key)
                .collect(),
        })
    }

    pub fn matches(&self, input: &PsbtInput, proprietary_prefix: &Vec<u8>) -> Result<(), ParticipantMatchError> {
        match Self::from_input_keyspend(input, proprietary_prefix) {
            Err(ParticipantError::DeserializeError) => { Err(ParticipantMatchError::DeserializeError) },
            Err(ParticipantError::NoParticipantsError) => { Err(ParticipantMatchError::NoParticipantsError) },
            Err(_) => {
                Err(ParticipantMatchError::ParticipantMatchError)
            },
            Ok(other) => {
                if self.participants == other.participants {
                    Ok(())
                } else {
                    Err(ParticipantMatchError::ParticipantMatchError)
                }
            },
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = &PublicKey> {
        self.participants.iter()
    }

    pub fn to_keyagg_cache<C: ZkpVerification>(&self, secp: &ZkpSecp256k1<C>) -> MusigKeyAggCache {
        let participant_keys: Vec<ZkpPublicKey> = self.participants.iter()
            .map(|pk| pk.to_zkp())
            .collect();

        MusigKeyAggCache::new(secp, &participant_keys[..])
    }
}

/// Context for generating nonces signing for the keyspend path
pub struct KeyspendContext<'a, C: ZkpSigning> {
    secp: &'a ZkpSecp256k1<C>,
    prefix: Vec<u8>,
    pubkey: ZkpPublicKey,
    participants: InputParticipants,
    absent_participants_valid: bool,
    keyagg_cache: MusigKeyAggCache,
    inner_agg_pk: ZkpXOnlyPublicKey,

    // TODO: enable and use and rename struct
    // tap_leaf: Option<TapBranchHash>,
}

#[derive(Debug)]
pub enum NonceGenerateError {
    NonceGenerateError,
    SighashError(SighashError),
    InvalidSighashError,
    SerializeError,
    DeserializeError,
    UnexpectedParticipants,
    InvalidInputIndexError,
    ChangedParticipantsError,
    NoParticipantsError,
    PlaceholderError,
}

impl<'a, C: ZkpVerification + ZkpSigning> KeyspendContext<'a, C> {
    pub fn from_participant_pubkeys(secp: &'a ZkpSecp256k1<C>, prefix: Vec<u8>, pubkey: PublicKey, participants: Vec<PublicKey>, merkle_root: Option<TapBranchHash>) -> Result<Self, AggregateError> {
        let participants = InputParticipants::from_participant_pubkeys(participants);

        let mut keyagg_cache = participants.to_keyagg_cache(secp);
        let (inner_agg_pk, _) = tweak_keyagg(secp, &mut keyagg_cache, merkle_root)
            .map_err(|_| AggregateError::InvalidTweakError)?;

        Ok(KeyspendContext {
            secp,
            prefix,
            pubkey: pubkey.to_zkp(),
            participants,
            absent_participants_valid: true,
            keyagg_cache,
            inner_agg_pk,
        })
    }

    pub fn updater(&'a self) -> Updater<'a, C> {
        Updater {
            secp: self.secp,
            //prefix: self.prefix.to_owned(),
            participants: &self.participants,
            keyagg_cache: &self.keyagg_cache,
            inner_agg_pk: self.inner_agg_pk,
            tap_leaf: None,
            merkle_root: None,
        }
    }

    /*
    fn normalize(&self, psbt: &mut PartiallySignedTransaction, input_index: usize) -> Result<Vec<PsbtNormalizeAction>, PsbtNormalizeError> {
        psbt.inputs
            .get(input_index)
            .ok_or(PsbtNormalizeError::InvalidInputIndexError)?;

        let mut actions: Vec<PsbtNormalizeAction> = Vec::new();

        let context = self.updater();

        let mut action = context.normalize_internal_key(psbt, input_index)
            .map_err(|e| PsbtNormalizeError::InternalKeyAddError(e))?;

        if action != PsbtNormalizeAction::NoAction {
            actions.push(action);
        }

        unimplemented!();
    }
    */

    pub fn generate_nonce(&'a self, psbt: &PartiallySignedTransaction, input_index: usize, session: MusigSessionId, extra_rand: [u8; 32]) -> Result<KeyspendSignContext<'a, C>, NonceGenerateError> {
        let input = psbt.inputs.get(input_index)
            .ok_or(NonceGenerateError::InvalidInputIndexError)?;

        let participants_validation_result = self.participants.matches(input, &self.prefix)
            .map_err(|e| match e {
                ParticipantMatchError::DeserializeError => {
                    NonceGenerateError::DeserializeError
                },
                ParticipantMatchError::ParticipantMatchError => {
                    NonceGenerateError::ChangedParticipantsError
                },
                ParticipantMatchError::NoParticipantsError => {
                    NonceGenerateError::NoParticipantsError
                },
            });

        match participants_validation_result {
            Ok(()) => Ok(()),
            Err(NonceGenerateError::NoParticipantsError)
                if self.absent_participants_valid => Ok(()),
            Err(e) => Err(e),
        }?;

        let sighash = taproot_keyspend_sighash(psbt, input_index)
            .map_err(|e| NonceGenerateError::SighashError(e))?;

        let sighash_message = Message::from_slice(&sighash.into_inner())
            .map_err(|_| NonceGenerateError::InvalidSighashError)?;

        let (secnonce, pubnonce) = self.keyagg_cache.nonce_gen(&self.secp, session,
            self.pubkey,
            sighash_message,
            Some(extra_rand.clone())
        )
            .map_err(|_| NonceGenerateError::NonceGenerateError)?;

        Ok(KeyspendSignContext {
            secp: self.secp,
            prefix: self.prefix.to_owned(),
            pubkey: self.pubkey,
            participants: &self.participants,
            keyagg_cache: &self.keyagg_cache,
            inner_agg_pk: self.inner_agg_pk,
            absent_participants_valid: self.absent_participants_valid,
            secnonce,
            pubnonce,
        })
    }

    pub fn add_nonce(&'a self, psbt: &mut PartiallySignedTransaction, input_index: usize, session: MusigSessionId, extra_rand: [u8; 32]) -> Result<KeyspendSignContext<'a, C>, NonceGenerateError> {
        let prefix = self.prefix.to_owned();

        let context = self.generate_nonce(psbt, input_index, session, extra_rand)?;

        let input = psbt.inputs
            .get_mut(input_index)
            .ok_or(NonceGenerateError::InvalidInputIndexError)?;

        let (key, value) = (self.pubkey.from_zkp(), context.pubnonce).to_psbt(&prefix)
            .map_err(|_| NonceGenerateError::SerializeError)?;

        // FIXME: handle case where key is already present, is that an error?
        input.proprietary
            .insert(key, value);

        Ok(context)
    }
}

/// Context to produce a partial signature
pub struct KeyspendSignContext<'a, C: ZkpVerification + ZkpSigning> {
    secp: &'a ZkpSecp256k1<C>,
    prefix: Vec<u8>,
    pubkey: ZkpPublicKey,
    participants: &'a InputParticipants,
    keyagg_cache: &'a MusigKeyAggCache,
    inner_agg_pk: ZkpXOnlyPublicKey,
    absent_participants_valid: bool,
    secnonce: MusigSecNonce,
    pub pubnonce: MusigPubNonce,
}

#[derive(Debug)]
/// Error from generating a partial signature
pub enum SignError {
    SignError,
    DeserializeError,
    SerializeError,
    MissingNonceError(PublicKey),
    InvalidInputIndexError,
    MissingInnerPubkey,
    AggregateKeyMismatch,
    SighashError,
    PlaceholderError,
    ChangedParticipantsError,
    NoParticipantsError,
}

impl<'a, C: ZkpVerification + ZkpSigning> KeyspendSignContext<'a, C> {
    pub fn get_partial_signature(self, privkey: &ZkpSecretKey, psbt: &PartiallySignedTransaction, input_index: usize) -> Result<(KeyspendSignatureAggregationContext<'a, C>, MusigPartialSignature), SignError> {
        let input = psbt.inputs
            .get(input_index)
            .ok_or(SignError::InvalidInputIndexError)?;

        let participants_validation_result = self.participants.matches(input, &self.prefix)
            .map_err(|e| match e {
                ParticipantMatchError::DeserializeError => {
                    SignError::DeserializeError
                },
                ParticipantMatchError::ParticipantMatchError => {
                    SignError::ChangedParticipantsError
                },
                ParticipantMatchError::NoParticipantsError => {
                    SignError::NoParticipantsError
                },
            });

        match participants_validation_result {
            Ok(()) => Ok(()),
            Err(SignError::NoParticipantsError)
                if self.absent_participants_valid => Ok(()),
            Err(e) => Err(e),
        }?;

        let psbt_inner_pk = input.tap_internal_key
            .ok_or(SignError::MissingInnerPubkey)?;

        if self.inner_agg_pk.from_zkp() != psbt_inner_pk {
            return Err(SignError::AggregateKeyMismatch);
        }

        let nonce_map = input.iter_proprietary::<PublicKey, MusigPubNonce>(&self.prefix)
            .collect::<Result<BTreeMap<_, _>, _>>()
            .map_err(|_| SignError::DeserializeError)?;

        let sorted_nonces: Vec<_> = self.participants.iter()
            .map(|&pk|
                 nonce_map.get(&pk)
                    .map(|&pk| pk)
                    .ok_or(SignError::MissingNonceError(pk))
             )
            .collect::<Result<Vec<MusigPubNonce>, _>>()?;

        let key_pair = ZkpKeyPair::from_secret_key(self.secp, privkey);

        let aggnonce = MusigAggNonce::new(self.secp, &sorted_nonces[..]);
        let sighash = taproot_keyspend_sighash(psbt, input_index)
            .map_err(|_| SignError::SighashError)?;

        let sighash_message = Message::from_slice(&sighash.into_inner())
            .map_err(|_| SignError::SighashError)?;

        let session = MusigSession::new(&self.secp, &self.keyagg_cache, aggnonce, sighash_message);

        // FIXME: improve error specificity
        let partial_signature = session.partial_sign(
            self.secp,
            self.secnonce,
            &key_pair,
            &self.keyagg_cache,
        )
        .map_err(|_| SignError::SignError)?;

        Ok((
            KeyspendSignatureAggregationContext {
                secp: self.secp,
                prefix: self.prefix,
                participants: self.participants,
                absent_participants_valid: self.absent_participants_valid,
                keyagg_cache: self.keyagg_cache,
                session,
                nonces: nonce_map,
            },
            partial_signature,
        ))
    }

    pub fn sign(self, privkey: &ZkpSecretKey, psbt: &mut PartiallySignedTransaction, input_index: usize) -> Result<KeyspendSignatureAggregationContext<'a, C>, SignError> {
        let pubkey = self.pubkey.from_zkp();
        let prefix = self.prefix.to_owned();
        let (agg_context, partial_signature) = self.get_partial_signature(privkey, psbt, input_index)?;

        let input = psbt.inputs
            .get_mut(input_index)
            .ok_or(SignError::InvalidInputIndexError)?;

        let (key, value) = (pubkey, partial_signature).to_psbt(&prefix)
            .map_err(|_| SignError::SerializeError)?;

        input.proprietary
            .insert(key, value);

        Ok(agg_context)
    }
}

#[derive(Debug)]
/// Error from aggregating signatures
pub enum SignatureAggregateError {
    InvalidInputIndexError,
    SignatureAggregateError,
    SignatureValidateError(PublicKey),
    NonceMissingError(PublicKey),
    SignatureMissingError(PublicKey),
    SignatureAndNonceMissingError(PublicKey),
    DeserializeError,
    IncompatibleSighashError,
    PlaceholderError,
    ChangedParticipantsError,
    NoParticipantsError,
}

/// Context to combine partial signatures, computing a final aggregate signature
pub struct KeyspendSignatureAggregationContext<'a, C: ZkpVerification + ZkpSigning> {
    secp: &'a ZkpSecp256k1<C>,
    prefix: Vec<u8>,
    keyagg_cache: &'a MusigKeyAggCache,
    session: MusigSession,
    participants: &'a InputParticipants,
    absent_participants_valid: bool,
    nonces: BTreeMap<PublicKey, MusigPubNonce>,
    // TODO
}

impl<'a, C: ZkpVerification + ZkpSigning> KeyspendSignatureAggregationContext<'a, C> {
    /// Validate and combine partial signatures, computing a final aggregate signature
    pub fn get_aggregate_signature(self, psbt: &PartiallySignedTransaction, input_index: usize) -> Result<ZkpSchnorrSignature, SignatureAggregateError> {
        let input = psbt.inputs
            .get(input_index)
            .ok_or(SignatureAggregateError::InvalidInputIndexError)?;

        let participants_validation_result = self.participants.matches(input, &self.prefix)
            .map_err(|e| match e {
                ParticipantMatchError::DeserializeError => {
                    SignatureAggregateError::DeserializeError
                },
                ParticipantMatchError::ParticipantMatchError => {
                    SignatureAggregateError::ChangedParticipantsError
                },
                ParticipantMatchError::NoParticipantsError => {
                    SignatureAggregateError::NoParticipantsError
                },
            });

        match participants_validation_result {
            Ok(()) => Ok(()),
            Err(SignatureAggregateError::NoParticipantsError)
                if self.absent_participants_valid => Ok(()),
            Err(e) => Err(e),
        }?;

        let iter = input.iter_proprietary::<PublicKey, MusigPartialSignature>(&self.prefix);

        let signatures = iter.collect::<Result<BTreeMap<PublicKey, MusigPartialSignature>, _>>()
            .map_err(|_| SignatureAggregateError::DeserializeError)?;

        let ordered_signatures = self.sort_and_validate_signatures(&signatures)?;

        Ok(self.session.partial_sig_agg(&ordered_signatures[..]))
    }

    /// Update a psbt input with a newly calculated aggregate signature
    pub fn aggregate_signatures(self, psbt: &mut PartiallySignedTransaction, input_index: usize) -> Result<(), SignatureAggregateError> {
        let signature = self.get_aggregate_signature(psbt, input_index)?;

        let input = psbt.inputs
            .get_mut(input_index)
            .ok_or(SignatureAggregateError::InvalidInputIndexError)?;

        let sighash = input.schnorr_hash_ty()
            .map_err(|_| SignatureAggregateError::IncompatibleSighashError)?;
        let schnorr_sig = SchnorrSig {
            sig: signature.from_zkp(),
            hash_ty: sighash,
        };

        input.tap_key_sig = Some(schnorr_sig);

        Ok(())
    }

    fn sort_and_validate_signatures(&self, signatures: &BTreeMap<PublicKey, MusigPartialSignature>) -> Result<Vec<MusigPartialSignature>, SignatureAggregateError> {
        self.nonces.iter()
            .map(|(pk, nonce)|
                match signatures.get(pk) {
                    Some(&partial_signature) => {
                        if self.session.partial_verify(
                            self.secp,
                            self.keyagg_cache,
                            partial_signature,
                            *nonce, pk.to_zkp()) {
                            Ok(partial_signature)
                        } else {
                            Err(SignatureAggregateError::SignatureValidateError(*pk))
                        }
                    },
                    None => {
                        Err(SignatureAggregateError::SignatureAndNonceMissingError(*pk))
                    },
                }
            )
            .collect::<Result<Vec<_>, _>>()
    }
}

#[derive(Debug)]
pub enum AddItemError {
    SerializeError,
    DuplicateKeyError,
}

/// Extra functionality for psbt input proprietary key/value pairs
pub trait PsbtInputHelper {

    /// Add a proprietary key/value pair
    fn add_proprietary_item<K: PsbtValue, V: PsbtValue> (&mut self, prefix: &ProprietaryPrefix, key: K, value: V) -> Result<(), AddItemError>
        where (K, V): ProprietaryKeyConvertible;

    fn add_participant(&mut self, prefix: &ProprietaryPrefix, index: ParticipantIndex, pubkey: &PublicKey) -> Result<(), AddItemError> {
        self.add_proprietary_item(prefix, index, pubkey.to_owned())
    }

    fn add_nonce(&mut self, prefix: &ProprietaryPrefix, pubkey: &PublicKey, nonce: &MusigPubNonce) -> Result<(), AddItemError> {
        self.add_proprietary_item(prefix, pubkey.to_owned(), nonce.to_owned())
    }

    fn add_partial_signature(&mut self, prefix: &ProprietaryPrefix, pubkey: &PublicKey, sig: &MusigPartialSignature) -> Result<(), AddItemError> {
        self.add_proprietary_item(prefix, pubkey.to_owned(), sig.to_owned())
    }

    /// Iterate over proprietary keys of a certain type in this psbt input
    fn iter_proprietary<'a, K: PsbtValue, V: PsbtValue>(&'a self, prefix: &'a ProprietaryPrefix) -> ProprietaryKeyIterator<'a, K, V>
        where (K, V): ProprietaryKeyConvertible;

}

/// Extra functionality for psbt input proprietary key/value pairs
impl PsbtInputHelper for PsbtInput {

    fn add_proprietary_item<K: PsbtValue, V: PsbtValue>(&mut self, prefix: &ProprietaryPrefix, key: K, value: V) -> Result<(), AddItemError>
        where (K, V): ProprietaryKeyConvertible
    {
        let (ser_key, ser_value) = (key, value).to_psbt(prefix)
            .map_err(|_| AddItemError::SerializeError)?;

        // FIXME: handle case where key is already present, is that an error? Probably not, since
        // any third party tampering could add a conflicting key to trigger an error, and any third
        // party could remove this key to give the appearance it is not present.
        // The signer cannot rely on the psbt to contain data containing state.
        // Out of scope but maybe the psbt *could* contain a required, authenticated, encrypted chunk of data, which could contain such information.
        self.proprietary
            .insert(ser_key, ser_value);

        Ok(())
    }

    fn iter_proprietary<'a, K: PsbtValue, V: PsbtValue>(&'a self, prefix: &'a ProprietaryPrefix) -> ProprietaryKeyIterator<'a, K, V>
        where (K, V): ProprietaryKeyConvertible {

        let protype = <(K, V) as ProprietaryKeyConvertible>::SUBTYPE;
        ProprietaryKeyIterator::<'a, K, V>::new(self.proprietary.iter(), &prefix[..], protype as ProprietaryType)
    }
}
