use bitcoin::{
    Address,
    SchnorrSighashType,
    Script,
    TxOut,
    Witness,
};

use bitcoin::psbt::{
    Input as PsbtInput,
    PsbtSighashType,
};

use bitcoin::network::constants::{
    Network,
};

use bitcoin::secp256k1::{
    PublicKey,
    Secp256k1,
    SecretKey,
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
    ParticipantPubkeysKeyValue,
    MusigPsbtInputSerializer,
    VariableLengthArray,
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
/// Error tweaking keyagg cache
pub enum TweakError {
    TweakError,
}

/// tweak a keyagg cache for a keyspend
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

    let txouts: Vec<&TxOut>;
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
    pub participant_pubkeys: Vec<PublicKey>,
    keyagg_cache: MusigKeyAggCache,
    pub inner_pk: ZkpXOnlyPublicKey,
    pub agg_pk: ZkpXOnlyPublicKey,
    pub merkle_root: Option<TapBranchHash>,
    pub tap_leaf: Option<TapLeafHash>,
}

#[derive(Debug)]
/// Error creating core context
pub enum CoreContextCreateError {
    InvalidTweak,
    InvalidInputIndex,
    DeserializeError,
}

#[derive(Debug)]
/// Error generating musig nonce
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

impl CoreContext {
    /// Create new core context
    pub fn new_key_spend<C: ZkpVerification>(secp: &ZkpSecp256k1<C>, participant_pubkeys: Vec<PublicKey>, merkle_root: Option<TapBranchHash>) -> Result<Self, CoreContextCreateError> {
        let mut keyagg_cache = Self::to_keyagg_cache(secp, &participant_pubkeys);

        let (inner_agg_pk, agg_pk) = tweak_keyagg(secp, &mut keyagg_cache, merkle_root)
            .map_err(|_| CoreContextCreateError::InvalidTweak)?;

        Ok(CoreContext {
            participant_pubkeys: participant_pubkeys,
            keyagg_cache,
            inner_pk: inner_agg_pk,
            agg_pk,
            merkle_root,
            tap_leaf: None,
        })
    }

    /// Create new script spend
    pub fn new_script_spend<C: ZkpVerification>(secp: &ZkpSecp256k1<C>, participant_pubkeys: Vec<PublicKey>, inner_pk: XOnlyPublicKey, merkle_root: TapBranchHash, tap_leaf: TapLeafHash) -> Result<Self, CoreContextCreateError> {
        let keyagg_cache = Self::to_keyagg_cache(secp, &participant_pubkeys);

        let agg_pk = keyagg_cache.agg_pk();

        Ok(CoreContext {
            participant_pubkeys: participant_pubkeys,
            keyagg_cache,
            inner_pk: inner_pk.to_zkp(),
            agg_pk,
            merkle_root: Some(merkle_root),
            tap_leaf: Some(tap_leaf),
        })
    }

    /// Create new core contexts from psbt input
    pub fn from_psbt_input<C: ZkpVerification>(secp: &ZkpSecp256k1<C>, input: &PsbtInput, psbt_keyvalue: &ParticipantPubkeysKeyValue) -> Result<Vec<Self>, CoreContextCreateError> {
        let (_agg_pk, VariableLengthArray(_participant_pubkeys)) = psbt_keyvalue;

        let mut result: Vec<Self> = Vec::new();

        if let Some(keyspend_context) = Self::from_keyspend_input(secp, input, psbt_keyvalue)? {
            result.push(keyspend_context);
        }

        // TODO: script path

        Ok(result)
    }

    fn to_keyagg_cache<C: ZkpVerification>(secp: &ZkpSecp256k1<C>, participant_pubkeys: &Vec<PublicKey>) -> MusigKeyAggCache {
        let zkp_participant_pubkeys: Vec<ZkpPublicKey> = participant_pubkeys.iter()
            .map(|pk| pk.to_zkp())
            .collect();

        MusigKeyAggCache::new(secp, &zkp_participant_pubkeys[..])
    }

    // TODO: allow derivation too
    /// Create new core context from an input's keyspend
    pub fn from_keyspend_input<C: ZkpVerification>(secp: &ZkpSecp256k1<C>, input: &PsbtInput, (agg_pk, VariableLengthArray(participant_pubkeys)): &ParticipantPubkeysKeyValue) -> Result<Option<Self>, CoreContextCreateError> {
        if input.tap_internal_key.as_ref() != Some(&agg_pk) {
            return Ok(None);
        }

        Ok(Some(
            Self::new_key_spend(secp,
                participant_pubkeys.to_owned(),
                input.tap_merkle_root
            )?
        ))
    }

    /// Calculate script pubkey
    pub fn script_pubkey<C: Verification>(&self, secp: &Secp256k1<C>) -> Script {
        Script::new_v1_p2tr(secp,
                            self.inner_pk.from_zkp(),
                            self.merkle_root)
    }

    /// Calculate address
    pub fn address<C: Verification>(&self, secp: &Secp256k1<C>, network: Network) -> Address {
        Address::p2tr(&secp, self.inner_pk.from_zkp(), self.merkle_root, network)
    }

    /// Is this context for a keyspend
    pub fn is_key_spend(&self) -> bool { self.tap_leaf.is_none() }

    fn psbt_key(&self) -> (XOnlyPublicKey, Option<TapLeafHash>) {
        (self.inner_pk.from_zkp(), self.tap_leaf)
    }

    fn psbt_key_with_pubkey(&self, pubkey: &ZkpPublicKey) -> (PublicKey, XOnlyPublicKey, Option<TapLeafHash>) {
        (pubkey.from_zkp(), self.inner_pk.from_zkp(), self.tap_leaf)
    }

    fn agg_pk_set(&self) -> BTreeSet<(XOnlyPublicKey, Option<TapLeafHash>)> {
        let mut result = BTreeSet::new();
        result.insert(self.psbt_key());
        result
    }

    /// Generate musig nonces
    pub fn generate_nonce<'a, C: ZkpVerification + ZkpSigning>(&'a self, secp: &ZkpSecp256k1<C>, pubkey: PublicKey, psbt: &PartiallySignedTransaction, input_index: usize, session: MusigSessionId, extra_rand: [u8; 32]) -> Result<SignContext<'a>, NonceGenerateError> {
        let sighash = taproot_sighash(psbt, input_index, self.tap_leaf)
            .map_err(|e| NonceGenerateError::SighashError(e))?;

        let sighash_message = Message::from_slice(&sighash.into_inner())
            .map_err(|_| NonceGenerateError::InvalidSighashError)?;

        let (secnonce, pubnonce) = self.keyagg_cache.nonce_gen(secp, session,
            pubkey.to_zkp(),
            sighash_message,
            Some(extra_rand.clone())
        )
            .map_err(|_| NonceGenerateError::NonceGenerateError)?;

        Ok(SignContext {
            core: &self,
            pubkey: pubkey.to_zkp(),
            secnonce,
            pubnonce,
        })
    }

    /// Generate musig nonces and add public nonce to PSBT
    pub fn add_nonce<'a, C: ZkpVerification + ZkpSigning>(&'a self, secp: &ZkpSecp256k1<C>, pubkey: PublicKey, psbt: &mut PartiallySignedTransaction, input_index: usize, session: MusigSessionId, extra_rand: [u8; 32]) -> Result<SignContext<'a>, NonceGenerateError> {
        let psbt_key = self.psbt_key_with_pubkey(&pubkey.to_zkp());

        let context = self.generate_nonce(secp, pubkey, psbt, input_index, session, extra_rand)?;

        let input = psbt.inputs
            .get_mut(input_index)
            .ok_or(NonceGenerateError::InvalidInputIndexError)?;

        input.add_item(psbt_key, context.pubnonce)
            .map_err(|_| NonceGenerateError::SerializeError)?;

        Ok(context)
    }
}

/// Context for creating a partial signature
pub struct SignContext<'a> {
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

impl<'a> SignContext<'a> {
    /// Calculate partial signature
    pub fn get_partial_signature<C: ZkpSigning>(self, secp: &ZkpSecp256k1<C>, privkey: &SecretKey, psbt: &PartiallySignedTransaction, input_index: usize) -> Result<(SignatureAggregateContext<'a>, MusigPartialSignature), SignError> {
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

        let key_pair = ZkpKeyPair::from_secret_key(secp, &privkey.to_zkp());

        let aggnonce = MusigAggNonce::new(secp, &sorted_nonces[..]);

        let sighash = taproot_sighash(psbt, input_index, self.core.tap_leaf)
            .map_err(|_| SignError::SighashError)?;

        let sighash_message = Message::from_slice(&sighash.into_inner())
            .map_err(|_| SignError::SighashError)?;

        let session = MusigSession::new(secp, &self.core.keyagg_cache, aggnonce, sighash_message);

        // FIXME: improve error specificity
        let partial_signature = session.partial_sign(
            secp,
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
                core: self.core,
                session,
                nonces: nonce_map,
            },
            partial_signature,
        ))
    }

    /// Calculate a partial signature on an input and add it to the PSBT
    pub fn sign<C: ZkpSigning>(self, secp: &ZkpSecp256k1<C>, privkey: &SecretKey, psbt: &mut PartiallySignedTransaction, input_index: usize) -> Result<SignatureAggregateContext<'a>, SignError> {
        let psbt_key = self.core.psbt_key_with_pubkey(&self.pubkey);

        let (agg_context, partial_signature) = self.get_partial_signature(secp, privkey, psbt, input_index)?;

        let input = psbt.inputs
            .get_mut(input_index)
            .ok_or(SignError::InvalidInputIndexError)?;

        input.add_item(psbt_key, partial_signature)
            .map_err(|_| SignError::SerializeError)?;

        Ok(agg_context)
    }
}

/// Context for aggregating musig partial signatures
pub struct SignatureAggregateContext<'a> {
    core: &'a CoreContext,
    session: MusigSession,
    nonces: BTreeMap<PublicKey, MusigPubNonce>,
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

impl<'a> SignatureAggregateContext<'a> {
    /// Validate and combine partial signatures, computing a final aggregate signature
    pub fn get_aggregate_signature<C: ZkpSigning>(self, secp: &ZkpSecp256k1<C>, psbt: &PartiallySignedTransaction, input_index: usize) -> Result<ZkpSchnorrSignature, SignatureAggregateError> {
        let input = psbt.inputs
            .get(input_index)
            .ok_or(SignatureAggregateError::InvalidInputIndexError)?;

        let agg_pk_set = self.core.agg_pk_set();

        let all_partial_signatures = input.get_partial_signatures_for(&agg_pk_set)
            .map_err(|_| SignatureAggregateError::DeserializeError)?;

        let partial_signatures = all_partial_signatures.get(&self.core.psbt_key())
            .ok_or(SignatureAggregateError::SignaturesMissingError)?;

        let ordered_signatures = self.sort_and_validate_signatures(secp, &partial_signatures)?;

        Ok(self.session.partial_sig_agg(&ordered_signatures[..]))
    }

    /// Update a psbt input with a newly calculated aggregate signature
    pub fn aggregate_signatures<C: ZkpSigning>(self, secp: &ZkpSecp256k1<C>, psbt: &mut PartiallySignedTransaction, input_index: usize) -> Result<(), SignatureAggregateError> {
        let agg_pk = self.core.agg_pk.from_zkp();
        let tap_leaf = self.core.tap_leaf;
        let signature = self.get_aggregate_signature(secp, psbt, input_index)?;

        let input = psbt.inputs
            .get_mut(input_index)
            .ok_or(SignatureAggregateError::InvalidInputIndexError)?;

        let sighash = input.schnorr_hash_ty()
            .map_err(|_| SignatureAggregateError::IncompatibleSighashError)?;

        let schnorr_sig = SchnorrSig {
            sig: signature.from_zkp(),
            hash_ty: sighash,
        };

        if let Some(tap_leaf_hash) = tap_leaf {
            input.tap_script_sigs.insert((agg_pk, tap_leaf_hash), schnorr_sig);
        } else {
            input.tap_key_sig = Some(schnorr_sig);
        }

        Ok(())
    }

    fn sort_and_validate_signatures<C: ZkpSigning>(&self, secp: &ZkpSecp256k1<C>, signatures: &BTreeMap<PublicKey, MusigPartialSignature>) -> Result<Vec<MusigPartialSignature>, SignatureAggregateError> {
        self.nonces.iter()
            .map(|(pk, nonce)|
                match signatures.get(pk) {
                    Some(&partial_signature) => {
                        if self.session.partial_verify(
                            secp,
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

pub trait PsbtInputHelper {
    fn get_tap_key_spend(&self) -> Option<Witness>;

    fn finalize_key_spend(&mut self) -> Option<Witness>;
}

impl PsbtInputHelper for PsbtInput {
    fn get_tap_key_spend(&self) -> Option<Witness> {
        let mut witness = Witness::new();

        if let Some(signature) = self.tap_key_sig {
            witness.push(signature.to_vec());

            Some(witness)
        } else {
            None
        }
    }

    fn finalize_key_spend(&mut self) -> Option<Witness> {
        let tap_key_spend = self.get_tap_key_spend();
        self.final_script_witness = tap_key_spend.clone();

        tap_key_spend
    }
}

/// Helper to enable easier interaction with PSBTs
pub trait PsbtHelper {
    fn get_input_script_pubkey(&self, index: usize) -> Option<&Script>;

    fn get_participating_for_pk<C: ZkpVerification>(&self, secp: &ZkpSecp256k1<C>, target_pubkey: &PublicKey) -> Result<Vec<(usize, CoreContext)>, CoreContextCreateError> {
        self.get_participating_by_pk(secp, |pks| {
            pks.iter()
                .any(|found_pubkey| found_pubkey == target_pubkey)
        })
    }

    fn get_participating_for_agg_pk<C: ZkpVerification>(&self, secp: &ZkpSecp256k1<C>, target_agg_pk: &XOnlyPublicKey) -> Result<Vec<(usize, CoreContext)>, CoreContextCreateError> {
        self.get_participating_by_agg_pk(secp, |found_agg_pk| {
            found_agg_pk == target_agg_pk
        })
    }

    fn get_participating_by_pk<C: ZkpVerification, F>(&self, secp: &ZkpSecp256k1<C>, f: F) -> Result<Vec<(usize, CoreContext)>, CoreContextCreateError>
    where
        F: FnMut(&Vec<PublicKey>) -> bool;

    fn get_participating_by_agg_pk<C: ZkpVerification, F>(&self, secp: &ZkpSecp256k1<C>, f: F) -> Result<Vec<(usize, CoreContext)>, CoreContextCreateError>
    where
        F: FnMut(&XOnlyPublicKey) -> bool;

    fn finalize_key_spends(&mut self);
}

impl PsbtHelper for PartiallySignedTransaction {
    // TODO: differentiate index out of bounds from other cases?
    fn get_input_script_pubkey(&self, index: usize) -> Option<&Script> {
        let psbt_input = self.inputs.get(index)?;

        if let Some(ref txout) = psbt_input.witness_utxo {
            return Some(&txout.script_pubkey);
        }


        if let Some(ref previous_tx) = psbt_input.non_witness_utxo {
            let input = self.unsigned_tx.input.get(index)?;

            //let previous_output = previous_tx.input.get(input.previous_output.vout.into())?;
            let previous_index = input.previous_output.vout as usize;
            let previous_output: &TxOut = previous_tx.output.get(previous_index)?;

            return Some(&previous_output.script_pubkey);
        }

        return None;
    }

    fn get_participating_by_pk<C: ZkpVerification, F>(&self, secp: &ZkpSecp256k1<C>, mut f: F) -> Result<Vec<(usize, CoreContext)>, CoreContextCreateError>
    where
        F: FnMut(&Vec<PublicKey>) -> bool,
    {
        let mut result: Vec<(usize, CoreContext)> = Vec::new();

        for (input_index, input) in self.inputs.iter().enumerate() {
            let participating = input.get_participating_by_pk(&mut f)
                .map_err(|_| CoreContextCreateError::DeserializeError)?;

            for participating_kv in participating.into_iter() {
                for ctx in CoreContext::from_psbt_input(secp, input, &participating_kv)?.into_iter() {
                    result.push((input_index, ctx));
                }
            }
        }

        Ok(result)
    }

    fn get_participating_by_agg_pk<C: ZkpVerification, F>(&self, secp: &ZkpSecp256k1<C>, mut f: F) -> Result<Vec<(usize, CoreContext)>, CoreContextCreateError>
    where
        F: FnMut(&XOnlyPublicKey) -> bool,
    {
        let mut result: Vec<(usize, CoreContext)> = Vec::new();

        for (input_index, input) in self.inputs.iter().enumerate() {
            let participating = input.get_participating_by_agg_pk(&mut f)
                .map_err(|_| CoreContextCreateError::DeserializeError)?;

            for participating_kv in participating.into_iter() {
                for ctx in CoreContext::from_psbt_input(secp, input, &participating_kv)?.into_iter() {
                    result.push((input_index, ctx));
                }
            }
        }

        Ok(result)
    }

    fn finalize_key_spends(&mut self) {
        for input in self.inputs.iter_mut() {
            input.finalize_key_spend();
        }
    }
}

#[derive(Debug)]
/// Result of adding spend info
pub enum SpendInfoAddResult {
    InputNoMatch, // XXX: Should this be an error?
    Success {
        internal_key_modified: bool,
        merkle_root_modified: bool,
    },
}

#[derive(Debug)]
/// Error from adding spend info
pub enum SpendInfoAddError {
    InvalidIndex,
    WitnessUtxoMissing,
    NoScriptPubkey,
}

#[derive(PartialEq, Debug)]
/// Result of adding participant set
pub enum ParticipantsAddResult {
    InputNoMatch, // XXX: Should this be an error?
    ParticipantsAdded,
}

#[derive(Debug)]
/// Error from adding participant set
pub enum ParticipantsAddError {
    InvalidIndex,
    SerializeError,
    NoScriptPubkey,
}

/// Helper to update PSBT with additional information
pub trait PsbtUpdater {
    fn add_spend_info<C: Verification>(&mut self, secp: &Secp256k1<C>, context: &CoreContext) -> Result<Vec<(usize, SpendInfoAddResult)>, SpendInfoAddError>;

    fn add_input_spend_info<C: Verification>(&mut self, secp: &Secp256k1<C>, context: &CoreContext, index: usize) -> Result<SpendInfoAddResult, SpendInfoAddError>;

    fn add_participants<C: Verification>(&mut self, secp: &Secp256k1<C>, context: &CoreContext) -> Result<Vec<(usize, ParticipantsAddResult)>, ParticipantsAddError>;

    fn add_input_participants<C: Verification>(&mut self, secp: &Secp256k1<C>, context: &CoreContext, index: usize) -> Result<ParticipantsAddResult, ParticipantsAddError>;
}

impl PsbtUpdater for PartiallySignedTransaction {
    fn add_spend_info<C: Verification>(&mut self, secp: &Secp256k1<C>, context: &CoreContext) -> Result<Vec<(usize, SpendInfoAddResult)>, SpendInfoAddError> {
        let mut result: Vec<_> = Vec::new();
        let input_len = self.inputs.len();

        for index in 0..input_len {
            let input_result = self.add_input_spend_info(secp, context, index)?;

            result.push((index, input_result));
        }

        Ok(result)
    }

    fn add_input_spend_info<C: Verification>(&mut self, secp: &Secp256k1<C>, context: &CoreContext, index: usize) -> Result<SpendInfoAddResult, SpendInfoAddError> {
        let script_pubkey = self.get_input_script_pubkey(index)
            .ok_or(SpendInfoAddError::NoScriptPubkey)?
            .clone();

        let input = self.inputs.get_mut(index)
            .ok_or(SpendInfoAddError::InvalidIndex)?;

        if script_pubkey.clone() != context.script_pubkey(secp) {
            return Ok(SpendInfoAddResult::InputNoMatch);
        }

        let mut internal_key_modified = false;
        let mut merkle_root_modified = false;

        let tap_internal_key = Some(context.inner_pk.from_zkp());

        if input.tap_internal_key != tap_internal_key {
            input.tap_internal_key = tap_internal_key;
            internal_key_modified = true;
        }

        if input.tap_merkle_root != context.merkle_root {
            input.tap_merkle_root = context.merkle_root;
            merkle_root_modified = true;
        }

        Ok(SpendInfoAddResult::Success {
            internal_key_modified,
            merkle_root_modified,
        })
    }

    fn add_participants<C: Verification>(&mut self, secp: &Secp256k1<C>, context: &CoreContext) -> Result<Vec<(usize, ParticipantsAddResult)>, ParticipantsAddError> {
        let mut result: Vec<_> = Vec::new();
        let input_len = self.inputs.len();

        for index in 0..input_len {
            let input_result = self.add_input_participants(secp, context, index)?;

            result.push((index, input_result));
        }

        Ok(result)
    }

    fn add_input_participants<C: Verification>(&mut self, secp: &Secp256k1<C>, context: &CoreContext, index: usize) -> Result<ParticipantsAddResult, ParticipantsAddError> {
        let script_pubkey = self.get_input_script_pubkey(index)
            .ok_or(ParticipantsAddError::NoScriptPubkey)?
            .clone();

        let input = self.inputs.get_mut(index)
            .ok_or(ParticipantsAddError::InvalidIndex)?;

        if script_pubkey.clone() != context.script_pubkey(secp) {
            return Ok(ParticipantsAddResult::InputNoMatch);
        }

        input.add_participants(context.inner_pk.from_zkp(), context.participant_pubkeys.as_ref())
            .map_err(|_| ParticipantsAddError::SerializeError)?;

        Ok(ParticipantsAddResult::ParticipantsAdded)
    }
}

