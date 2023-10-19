use bitcoin::{
    SchnorrSighashType,
    Script,
    TxOut,
};

use bitcoin::psbt::{
    Input as PsbtInput,
    PsbtSighashType,
};

use bitcoin::secp256k1::{
    PublicKey,
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
    TapLeafHash,
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
    XOnlyPublicKey,
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
    deserialize_key,
    deserialize_value,
    filter_key_type,
    map_kv_results,
    PsbtKeyValue,
    PsbtValue,
    ToPsbtKeyValue,

    PsbtInputHelper,
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
pub fn taproot_sighash(psbt: &PartiallySignedTransaction, input_index: usize, tap_leaf: Option<TapLeafHash>) -> Result<TapSighashHash, SighashError> {
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

    let annex = None; // TODO: Support one day when it matters
    let separator: u32 = 0xFFFFFFFF; // FIXME: verify, understand
    let leaf_hash_separator = tap_leaf.map(|lh| (lh, separator));

    let mut cache = SighashCache::new(&psbt.unsigned_tx);
    cache.taproot_signature_hash(input_index, &prevouts, annex, leaf_hash_separator, psbt_sighash)
        .map_err(|_| SighashError::SighashError)
}

/// Base context for musig operations
pub struct CoreContext {
    participant_pubkeys: Vec<PublicKey>,
    keyagg_cache: MusigKeyAggCache,
    inner_agg_pk: ZkpXOnlyPublicKey,
    agg_pk: ZkpXOnlyPublicKey,
    merkle_root: Option<TapBranchHash>,
    tap_leaf: Option<TapLeafHash>,
}

#[derive(Debug)]
pub enum CoreContextCreateError {
    TweakError,
}

impl CoreContext {
    //fn from_participants<C: ZkpVerification>(secp: &ZkpSecp256k1<C>, 
    fn to_keyagg_cache<C: ZkpVerification>(secp: &ZkpSecp256k1<C>, participant_pubkeys: &Vec<PublicKey>) -> MusigKeyAggCache {
        let zkp_participant_pubkeys: Vec<ZkpPublicKey> = participant_pubkeys.iter()
            .map(|pk| pk.to_zkp())
            .collect();

        MusigKeyAggCache::new(secp, &zkp_participant_pubkeys[..])
    }

    pub fn new_keyspend<C: ZkpVerification>(secp: &ZkpSecp256k1<C>, participant_pubkeys: Vec<PublicKey>, merkle_root: Option<TapBranchHash>) -> Result<Self, CoreContextCreateError> {
        let mut keyagg_cache = Self::to_keyagg_cache(secp, &participant_pubkeys);

        let (inner_agg_pk, agg_pk) = tweak_keyagg(secp, &mut keyagg_cache, merkle_root)
            .map_err(|_| CoreContextCreateError::TweakError)?;

        Ok(CoreContext {
            participant_pubkeys,
            keyagg_cache,
            inner_agg_pk,
            agg_pk,
            merkle_root,
            tap_leaf: None,
        })
    }

    pub fn new_script_spend<C: ZkpVerification>(secp: &ZkpSecp256k1<C>, participant_pubkeys: Vec<PublicKey>, merkle_root: TapBranchHash, tap_leaf: TapLeafHash) -> Result<Self, CoreContextCreateError> {
        let mut keyagg_cache = Self::to_keyagg_cache(secp, &participant_pubkeys);

        let agg_pk = keyagg_cache.agg_pk();

        Ok(CoreContext {
            participant_pubkeys,
            keyagg_cache,
            inner_agg_pk: agg_pk,
            agg_pk,
            merkle_root: None,
            tap_leaf: Some(tap_leaf),
        })
    }

    fn is_keyspend(&self) -> bool { self.tap_leaf.is_none() }

    fn psbt_key(&self) -> (XOnlyPublicKey, Option<TapLeafHash>) {
        (self.inner_agg_pk.from_zkp(), self.tap_leaf)
    }

    fn agg_pk_set(&self) -> BTreeSet<(XOnlyPublicKey, Option<TapLeafHash>)> {
        let mut result = BTreeSet::new();
        result.insert(self.psbt_key());
        result
    }

    pub fn updater<'a, C: ZkpSigning>(&'a self, secp: &'a ZkpSecp256k1<C>) -> Updater<'a, C> {
        Updater {
            secp,
            participant_pubkeys: &self.participant_pubkeys,
            keyagg_cache: &self.keyagg_cache,
            inner_agg_pk: self.inner_agg_pk,
            tap_leaf: None, // FIXME
            merkle_root: self.merkle_root,
        }
    }
}

/// Context for generating nonces for signing
pub struct NonceGenerateContext<'a, C: ZkpSigning> {
    secp: &'a ZkpSecp256k1<C>,
    core: &'a CoreContext,
    pubkey: ZkpPublicKey,
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

impl<'a, C: ZkpVerification + ZkpSigning> NonceGenerateContext<'a, C> {
    /// Generate a nonce for signing
    pub fn generate_nonce(&'a self, psbt: &PartiallySignedTransaction, input_index: usize, session: MusigSessionId, extra_rand: [u8; 32]) -> Result<SignContext<'a, C>, NonceGenerateError> {
        let input = psbt.inputs.get(input_index)
            .ok_or(NonceGenerateError::InvalidInputIndexError)?;

        let sighash = taproot_sighash(psbt, input_index, self.core.tap_leaf)
            .map_err(|e| NonceGenerateError::SighashError(e))?;

        let sighash_message = Message::from_slice(&sighash.into_inner())
            .map_err(|_| NonceGenerateError::InvalidSighashError)?;

        let (secnonce, pubnonce) = self.core.keyagg_cache.nonce_gen(&self.secp, session,
            self.pubkey,
            sighash_message,
            Some(extra_rand.clone())
        )
            .map_err(|_| NonceGenerateError::NonceGenerateError)?;

        Ok(SignContext {
            secp: self.secp,
            core: self.core,
            pubkey: self.pubkey,
            secnonce,
            pubnonce,
        })
    }

    pub fn add_nonce(&'a self, psbt: &mut PartiallySignedTransaction, input_index: usize, session: MusigSessionId, extra_rand: [u8; 32]) -> Result<SignContext<'a, C>, NonceGenerateError> {

        let context = self.generate_nonce(psbt, input_index, session, extra_rand)?;

        let input = psbt.inputs
            .get_mut(input_index)
            .ok_or(NonceGenerateError::InvalidInputIndexError)?;

        let (key, value) = (self.pubkey.from_zkp(), context.pubnonce).to_psbt()
            .map_err(|_| NonceGenerateError::SerializeError)?;

        // FIXME: handle case where key is already present, is that an error?
        input.unknown
            .insert(key, value);

        Ok(context)
    }
}

/// Context for creating a partial signature
pub struct SignContext<'a, C: ZkpVerification + ZkpSigning> {
    secp: &'a ZkpSecp256k1<C>,
    core: &'a CoreContext,
    pubkey: ZkpPublicKey,
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
    MissingNoncesError,
    InvalidInputIndexError,
    MissingInnerPubkey,
    AggregateKeyMismatch,
    SighashError,
    PlaceholderError,
    ChangedParticipantsError,
    NoParticipantsError,
}

impl<'a, C: ZkpVerification + ZkpSigning> SignContext<'a, C> {
    /// Calculate partial signature
    pub fn get_partial_signature(self, privkey: &ZkpSecretKey, psbt: &PartiallySignedTransaction, input_index: usize) -> Result<(SignatureAggregateContext<'a, C>, MusigPartialSignature), SignError> {
        let input = psbt.inputs
            .get(input_index)
            .ok_or(SignError::InvalidInputIndexError)?;

        let agg_pk_set = self.core.agg_pk_set();

        let all_pubnonces = input.get_public_nonces_for(&agg_pk_set)
            .map_err(|_| SignError::DeserializeError)?;

        let pubnonces = all_pubnonces.get(&self.core.psbt_key())
            .ok_or(SignError::MissingNoncesError)?;

        let sorted_nonces: Vec<_> = self.core.participant_pubkeys.iter()
            .map(|&pk|
                 pubnonces.get(&pk)
                    .map(|&pk| pk)
                    .ok_or(SignError::MissingNonceError(pk))
             )
            .collect::<Result<Vec<MusigPubNonce>, _>>()?;

        let key_pair = ZkpKeyPair::from_secret_key(self.secp, privkey);

        let aggnonce = MusigAggNonce::new(self.secp, &sorted_nonces[..]);

        let sighash = taproot_sighash(psbt, input_index, self.core.tap_leaf)
            .map_err(|_| SignError::SighashError)?;

        let sighash_message = Message::from_slice(&sighash.into_inner())
            .map_err(|_| SignError::SighashError)?;

        let session = MusigSession::new(&self.secp, &self.core.keyagg_cache, aggnonce, sighash_message);

        // FIXME: improve error specificity
        let partial_signature = session.partial_sign(
            self.secp,
            self.secnonce,
            &key_pair,
            &self.core.keyagg_cache,
        )
        .map_err(|_| SignError::SignError)?;

        let nonce_map = self.core.participant_pubkeys.iter()
            .map(|&pk|
                pubnonces.get(&pk)
                    .map(|&nonce| (pk, nonce))
                    .ok_or(SignError::MissingNonceError(pk))
             )
            .collect::<Result<BTreeMap<PublicKey, MusigPubNonce>, _>>()?;

        Ok((
            SignatureAggregateContext {
                secp: self.secp,
                core: self.core,
                session,
                nonces: nonce_map,
            },
            partial_signature,
        ))
    }

    pub fn sign(self, privkey: &ZkpSecretKey, psbt: &mut PartiallySignedTransaction, input_index: usize) -> Result<SignatureAggregateContext<'a, C>, SignError> {
        let pubkey = self.pubkey.from_zkp();
        let (agg_context, partial_signature) = self.get_partial_signature(privkey, psbt, input_index)?;

        let input = psbt.inputs
            .get_mut(input_index)
            .ok_or(SignError::InvalidInputIndexError)?;

        let (key, value) = (pubkey, partial_signature).to_psbt()
            .map_err(|_| SignError::SerializeError)?;

        input.unknown
            .insert(key, value);

        Ok(agg_context)
    }
}

pub struct SignatureAggregateContext<'a, C: ZkpVerification + ZkpSigning> {
    secp: &'a ZkpSecp256k1<C>,
    core: &'a CoreContext,
    session: MusigSession,
    nonces: BTreeMap<PublicKey, MusigPubNonce>,
    // TODO
}

#[derive(Debug)]
/// Error from aggregating signatures
pub enum SignatureAggregateError {
    InvalidInputIndexError,
    SignatureAggregateError,
    SignatureValidateError(PublicKey),
    NonceMissingError(PublicKey),
    SignatureMissingError(PublicKey),
    SignaturesMissingError,
    SignatureAndNonceMissingError(PublicKey),
    DeserializeError,
    IncompatibleSighashError,
    PlaceholderError,
    ChangedParticipantsError,
    NoParticipantsError,
}

impl<'a, C: ZkpVerification + ZkpSigning> SignatureAggregateContext<'a, C> {
    /// Validate and combine partial signatures, computing a final aggregate signature
    pub fn get_aggregate_signature(self, psbt: &PartiallySignedTransaction, input_index: usize) -> Result<ZkpSchnorrSignature, SignatureAggregateError> {
        let input = psbt.inputs
            .get(input_index)
            .ok_or(SignatureAggregateError::InvalidInputIndexError)?;

        let agg_pk_set = self.core.agg_pk_set();

        let all_partial_signatures = input.get_partial_signatures_for(&agg_pk_set)
            .map_err(|_| SignatureAggregateError::DeserializeError)?;

        let partial_signatures = all_partial_signatures.get(&self.core.psbt_key())
            .ok_or(SignatureAggregateError::SignaturesMissingError)?;

        let ordered_signatures = self.sort_and_validate_signatures(&partial_signatures)?;

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
                            &self.core.keyagg_cache,
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

// FIXME: near duplicate of CoreContext
pub struct Updater<'a, C: ZkpSigning> {
    secp: &'a ZkpSecp256k1<C>,
    participant_pubkeys: &'a Vec<PublicKey>,
    keyagg_cache: &'a MusigKeyAggCache,
    inner_agg_pk: ZkpXOnlyPublicKey,
    tap_leaf: Option<TapBranchHash>,
    merkle_root: Option<TapBranchHash>,
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

pub enum ParticipantError {
    MissingParticipantsKey,
    NoParticipantsError,
    DuplicateParticipantError,
    DeserializeError,
}
