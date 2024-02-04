use bitcoin::{
    Address,
    Network,
    OutPoint,
    Script,
    ScriptBuf,
    TxOut,
    Witness,
};

use bitcoin::bip32::{
    Fingerprint,
    ChainCode,
    ChildNumber,
    DerivationPath,
    ExtendedPubKey,
};

use bitcoin::psbt::{
    Input as PsbtInput,
    PsbtSighashType,
};

use bitcoin::secp256k1::{
    PublicKey,
    Secp256k1,
    SecretKey,
    Verification,
};

use bitcoin::sighash::{
    Prevouts,
    SighashCache,
    TapSighash,
    TapSighashType,
};

use bitcoin::taproot::{
    Signature,
    TapLeafHash,
    TapNodeHash,
    TapTweakHash,
};

use bitcoin::secp256k1::{
    XOnlyPublicKey,
};

use bitcoin::psbt::{
    PartiallySignedTransaction,
};

use secp256k1_zkp::{
    Message,
    MusigAggNonce,
    MusigKeyAggCache,
    MusigPartialSignature,
    MusigPubNonce,
    MusigSecNonce,
    MusigSession,
    MusigSessionId,
    Keypair as ZkpKeyPair,
    PublicKey as ZkpPublicKey,
    schnorr::Signature as ZkpSchnorrSignature,
    Secp256k1 as ZkpSecp256k1,
    SecretKey as ZkpSecretKey,
    Signing as ZkpSigning,
    Verification as ZkpVerification,
    XOnlyPublicKey as ZkpXOnlyPublicKey,
};

use std::cmp::Ordering;
use std::collections::{
    btree_map::BTreeMap,
    btree_map::Entry,
    btree_set::BTreeSet,
    HashMap,
    HashSet,
};

use std::fmt::{
    Display,
    Error as FmtError,
    Formatter,
};
use std::iter::{once, empty, FromIterator};

use crate::{
    DeserializeError,
    SerializeError,
    SerializeOrDeserializeError,
    FromZkp,
    PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS,
    PSBT_IN_MUSIG2_PUB_NONCE,
    PSBT_IN_MUSIG2_PARTIAL_SIG,
    ToZkp,
};

use crate::serialize::{
    MusigPsbt,
    MusigPsbtInput,
    MusigPsbtKeyValue,
    ParticipantPubkeysKeyValue,
    MusigPsbtInputSerializer,
    VariableLengthArray,
};

// This is the precomputed result of sha256("Musig2Musig2Musig2") per the BIP
const MUSIG_ROOT_CHAIN_CODE: [u8; 32] = [
    0x86, 0x80, 0x87, 0xca, 0x02, 0xa6, 0xf9, 0x74, 0xc4, 0x59, 0x89, 0x24, 0xc3, 0x6b, 0x57, 0x76, 0x2d, 0x32, 0xcb, 0x45, 0x71, 0x71, 0x67, 0xe3, 0x00, 0x62, 0x2c, 0x71, 0x67, 0xe3, 0x89, 0x65
];

pub fn max_by<T, K, I, F, C>(i: I, f: F, cmp: C) -> BTreeMap<K, T>
where
    K: Ord,
    I: Iterator<Item=T>,
    F: Fn(&T) -> K,
    C: Fn(&T, &T) -> Ordering,
{
    let mut result: BTreeMap<K, T> = BTreeMap::new();

    for item in i {
        let key = f(&item);

        match result.entry(key) {
            Entry::Vacant(entry) => {
                entry.insert(item);
            }
            Entry::Occupied(mut entry) => {
                if cmp(&entry.get(), &item) == Ordering::Less {
                    entry.insert(item);
                }
            }
        }
    }

    result
}

/// The type of the index of a participant in an aggregate signing
pub type ParticipantIndex = u32;

/// An error when generating the sighash when signing for a taproot
/// input
#[derive(Debug)]
pub enum SighashError {
    InvalidInputIndexError,
    IncompatibleSighashError(PsbtSighashType),
    UnimplementedSighashError(TapSighashType),
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
    DerivationError,
}

pub fn musig_agg_pk_to_xpub(pk: PublicKey, network: Network) -> ExtendedPubKey {
    ExtendedPubKey {
        network, // Safe?
        depth: 0,
        parent_fingerprint: Default::default(),
        child_number: ChildNumber::Normal{index: 0},
        public_key: pk,
        chain_code: ChainCode::from(MUSIG_ROOT_CHAIN_CODE),
    }
}

// Takes an owned keyagg cache so that we cant't return an invalid keyagg_cache in case of an error
// partway through derivation
fn derive_keyagg<C, I>(secp: &ZkpSecp256k1<C>, mut keyagg_cache: MusigKeyAggCache, derivation_path: I) -> Result<MusigKeyAggCache, TweakError>
where
    C: ZkpVerification,
    I: IntoIterator<Item=ChildNumber>,
{
    // FIXME: don't hard code network
    let mut xpub = musig_agg_pk_to_xpub(keyagg_cache.agg_pk_full().from_zkp(), Network::Bitcoin);

    for child_number in derivation_path.into_iter() {
        let (tweak, chain_code) = xpub.ckd_pub_tweak(child_number)
            .map_err(|_| TweakError::DerivationError)?;

        keyagg_cache.pubkey_ec_tweak_add(secp, tweak.to_zkp())
            .map_err(|_| TweakError::DerivationError)?;

        xpub = ExtendedPubKey {
            network: Network::Bitcoin, // Safe?
            depth: xpub.depth + 1,
            parent_fingerprint: Default::default(),
            child_number,
            chain_code,
            public_key: keyagg_cache.agg_pk_full().from_zkp(),
        };
    }

    Ok(keyagg_cache)
}

/// tweak a keyagg cache for a keyspend
fn tweak_keyagg_keyspend<C: ZkpVerification>(secp: &ZkpSecp256k1<C>, keyagg_cache: &mut MusigKeyAggCache, merkle_root: Option<TapNodeHash>) -> Result<ZkpPublicKey, TweakError> {
    let inner_pk = keyagg_cache.agg_pk();

    let tweak = TapTweakHash::from_key_and_tweak(inner_pk.from_zkp(), merkle_root);

    let tweak_key = ZkpSecretKey::from_slice(tweak.as_ref())
        .map_err(|_| TweakError::TweakError)?; // tweak is not a valid private key

    let tweaked_pk = keyagg_cache.pubkey_xonly_tweak_add(secp, tweak_key)
        .map_err(|_| TweakError::TweakError)?; // tweak negates agg pk

    Ok(tweaked_pk)
}

/// Generate the sighash to sign for a taproot input
pub fn taproot_sighash(psbt: &PartiallySignedTransaction, input_index: usize, tap_leaf: Option<TapLeafHash>) -> Result<TapSighash, SighashError> {
    let psbt_input = psbt.inputs.get(input_index)
        .ok_or(SighashError::InvalidInputIndexError)?;

    let sighash_type = psbt_input.sighash_type
        .unwrap_or(TapSighashType::Default.into());

    let psbt_sighash = sighash_type.taproot_hash_ty()
        .map_err(|_| SighashError::IncompatibleSighashError(sighash_type))?;

    let txouts: Vec<&TxOut>;
    let prevouts: Prevouts<_> = match psbt_sighash {
        TapSighashType::None | TapSighashType::NonePlusAnyoneCanPay => {
            return Err(SighashError::UnimplementedSighashError(psbt_sighash));
        },
        TapSighashType::Default | TapSighashType::All | TapSighashType::Single => {
            let fallible_txouts: Result<Vec<&TxOut>, _> = psbt.inputs.iter()
                .enumerate()
                .map(|(i, input)| match &input.witness_utxo {
                    &None => Err(SighashError::MissingPrevoutError(i)),
                    &Some(ref prevout) => Ok(prevout),
                }).collect();

            txouts = fallible_txouts?;
            Prevouts::All(&txouts[..])
        },
        TapSighashType::AllPlusAnyoneCanPay | TapSighashType::SinglePlusAnyoneCanPay => {
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
    /// The compressed aggregate public key used as a lookup key in the PSBT
    pub key_agg_pk: ZkpPublicKey,
    pub tap_leaf: Option<TapLeafHash>,
}

#[derive(Debug)]
/// Error creating core context
pub enum CoreContextCreateError {
    InvalidTweak,
    InvalidInputIndex,
    //DeserializeError,
    Placeholder,
}

#[derive(Debug)]
/// Error creating core context from PSBT input
pub enum CoreContextFromInputError {
    /// Error building the context
    ContextCreateError(CoreContextCreateError),
    /// PSBT input is missing a required key
    MissingKey,
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

/// Convenience struct to carry around script pubkey info
/// Intended to be created by the application, never derived from the psbt
pub struct TaprootScriptPubkey {
    pub internal_key: XOnlyPublicKey,
    pub merkle_root: Option<TapNodeHash>,
}

impl TaprootScriptPubkey {
    pub fn from_participant_keys<C: ZkpVerification>(secp: &ZkpSecp256k1<C>, participant_pubkeys: Vec<PublicKey>, merkle_root: Option<TapNodeHash>) -> Self {
        let keyagg_cache = CoreContext::to_keyagg_cache(secp, participant_pubkeys.iter());

        Self {
            internal_key: keyagg_cache.agg_pk().from_zkp(),
            merkle_root,
        }
    }
    /// Calculate script pubkey
    pub fn script_pubkey<C: Verification>(&self, secp: &Secp256k1<C>) -> ScriptBuf {
        ScriptBuf::new_v1_p2tr(secp, self.internal_key, self.merkle_root)
    }

    /// Calculate address
    pub fn address<C: Verification>(&self, secp: &Secp256k1<C>, network: Network) -> Address {
        Address::p2tr(&secp, self.internal_key, self.merkle_root, network)
    }
}

impl CoreContext {
    pub fn from_input<C: ZkpVerification>(secp: &ZkpSecp256k1<C>, input: &PsbtInput, pubkeys: Vec<PublicKey>, tap_leaf: Option<TapLeafHash>, derivation_path: &DerivationPath) -> Result<Self, CoreContextCreateError> {
        if let Some(tap_leaf) = tap_leaf {
            CoreContext::new_script_spend(secp,
                                          pubkeys, tap_leaf, derivation_path)
        } else {
            CoreContext::new_key_spend(secp,
                                       pubkeys,
                                       input.tap_merkle_root.clone(), derivation_path)
        }
    }

    /// Create new core context
    pub fn new_key_spend<C>(secp: &ZkpSecp256k1<C>, participant_pubkeys: Vec<PublicKey>, merkle_root: Option<TapNodeHash>, derivation_path: &DerivationPath) -> Result<Self, CoreContextCreateError>
    where
        C: ZkpVerification,
    {
        let keyagg_cache = Self::to_keyagg_cache(secp, participant_pubkeys.iter());

        let key_agg_pk = keyagg_cache.agg_pk_full();

        let mut keyagg_cache = derive_keyagg(secp, keyagg_cache, derivation_path.into_iter().cloned())
            .map_err(|_| CoreContextCreateError::InvalidTweak)?;

        let _agg_pk = tweak_keyagg_keyspend(secp, &mut keyagg_cache, merkle_root)
            .map_err(|_| CoreContextCreateError::InvalidTweak)?;

        Ok(CoreContext {
            participant_pubkeys: participant_pubkeys,
            keyagg_cache,
            key_agg_pk,
            tap_leaf: None,
        })
    }

    /// Create new script spend
    pub fn new_script_spend<C: ZkpVerification>(secp: &ZkpSecp256k1<C>, participant_pubkeys: Vec<PublicKey>, tap_leaf: TapLeafHash, derivation_path: &DerivationPath) -> Result<Self, CoreContextCreateError> {
        let keyagg_cache = Self::to_keyagg_cache(secp, participant_pubkeys.iter());

        let key_agg_pk = keyagg_cache.agg_pk_full();

        let keyagg_cache = derive_keyagg(secp, keyagg_cache, derivation_path.into_iter().cloned())
            .map_err(|_| CoreContextCreateError::InvalidTweak)?;

        Ok(CoreContext {
            participant_pubkeys,
            keyagg_cache,
            key_agg_pk,
            tap_leaf: Some(tap_leaf),
        })
    }

    /// Create new core contexts from psbt input
    pub fn from_psbt_input<C: ZkpVerification>(secp: &ZkpSecp256k1<C>, input: &PsbtInput, psbt_keyvalue: &ParticipantPubkeysKeyValue, derivation: DerivationPath) -> Result<Vec<Self>, CoreContextCreateError> {
        let (_agg_pk, VariableLengthArray(participant_pubkeys)) = psbt_keyvalue;

        let mut result: Vec<Self> = Vec::new();

        if let Some(keyspend_context) = Self::from_keyspend_input(secp, input, participant_pubkeys, derivation)? {
            result.push(keyspend_context);
        }

        // TODO: script path

        Ok(result)
    }

    fn to_keyagg_cache<'a, I: Iterator<Item=&'a PublicKey>, C: ZkpVerification>(secp: &ZkpSecp256k1<C>, participant_pubkeys: I) -> MusigKeyAggCache {
        let zkp_participant_pubkeys: Vec<ZkpPublicKey> = participant_pubkeys
            .map(|pk| pk.to_zkp())
            .collect();

        MusigKeyAggCache::new(secp, &zkp_participant_pubkeys[..])
    }

    // TODO: allow derivation too
    /// Create new core context from an input's keyspend
    pub fn from_keyspend_input<C: ZkpVerification>(secp: &ZkpSecp256k1<C>, input: &PsbtInput, participant_pubkeys: &[PublicKey], derivation: DerivationPath) -> Result<Option<Self>, CoreContextCreateError> {
        Ok(Some(
            Self::new_key_spend(secp,
                participant_pubkeys.to_owned(),
                input.tap_merkle_root,
                &derivation,
            )?
        ))
    }

    /// Is this context for a keyspend
    pub fn is_key_spend(&self) -> bool { self.tap_leaf.is_none() }

    pub fn xonly_key(&self) -> XOnlyPublicKey {
        self.keyagg_cache.agg_pk().from_zkp()
    }

    fn psbt_key(&self) -> (PublicKey, Option<TapLeafHash>) {
        (self.key_agg_pk.from_zkp(), self.tap_leaf)
    }

    fn psbt_key_with_pubkey(&self, pubkey: &ZkpPublicKey) -> (PublicKey, PublicKey, Option<TapLeafHash>) {
        (pubkey.from_zkp(), self.key_agg_pk.from_zkp(), self.tap_leaf)
    }

    fn agg_pk_set(&self) -> BTreeSet<(PublicKey, Option<TapLeafHash>)> {
        let mut result = BTreeSet::new();
        result.insert(self.psbt_key());
        result
    }

    /// Generate musig nonces
    pub fn generate_nonce<'a, C: ZkpVerification + ZkpSigning>(&'a self, secp: &ZkpSecp256k1<C>, pubkey: PublicKey, psbt: &PartiallySignedTransaction, input_index: usize, session: MusigSessionId, extra_rand: [u8; 32]) -> Result<SignContext<'a>, NonceGenerateError> {
        let sighash = taproot_sighash(psbt, input_index, self.tap_leaf)
            .map_err(|e| NonceGenerateError::SighashError(e))?;

        let sighash_message = Message::from_digest_slice(sighash.as_ref())
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
    pub fn add_nonce<'a, C: ZkpVerification + ZkpSigning>(&'a self, secp: &ZkpSecp256k1<C>, pubkey: PublicKey, psbt: &mut MusigPsbt, input_index: usize, session: MusigSessionId, extra_rand: [u8; 32]) -> Result<SignContext<'a>, NonceGenerateError> {
        let psbt_key = self.psbt_key_with_pubkey(&pubkey.to_zkp());

        let context = self.generate_nonce(secp, pubkey, psbt, input_index, session, extra_rand)?;

        let input = psbt.inputs
            .get_mut(input_index)
            .ok_or(NonceGenerateError::InvalidInputIndexError)?;

        input.add_item(psbt_key, context.pubnonce)
            .map_err(|_| NonceGenerateError::SerializeError)?;

        // FIXME: a bit jank to maintain the parallel MusigPsbtInput as a cache but oh well...
        // Maybe I can hide the real psbt inside and only use the cache if/until it gets serialized
        // out
        let musig_input = psbt.musig_inputs.get_mut(input_index)
            .ok_or(NonceGenerateError::InvalidInputIndexError)?;
        musig_input.public_nonce.insert(psbt_key, context.pubnonce);

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
    pub fn get_partial_signature<C: ZkpSigning>(self, secp: &ZkpSecp256k1<C>, privkey: &SecretKey, psbt: &MusigPsbt, input_index: usize) -> Result<(SignatureAggregateContext<'a>, MusigPartialSignature), SignError> {
        let (input, musig_input) = psbt.get_input(input_index)
            .ok_or(SignError::InvalidInputIndexError)?;

        let agg_pk_set = self.core.agg_pk_set();

        let pubnonces: BTreeMap<PublicKey, MusigPubNonce> = musig_input.public_nonce.iter()
            .filter_map(|((pk, agg_pk, tap_leaf), pub_nonce)| {
                // FIXME: make sure we're using the right agg_pk in case of derivation
                // bip specifies this, I think it's the un-tweaked...
                if (*agg_pk, *tap_leaf) != (self.core.key_agg_pk.from_zkp(), self.core.tap_leaf) {
                    return None;
                }

                Some((pk.clone(), pub_nonce.clone()))
            })
            .collect();

        let sorted_nonces: Vec<_> = self.core.participant_pubkeys.iter()
            .map(|&pk| {
                 pubnonces.get(&pk)
                    .map(|&pk| pk)
                    .ok_or(SignError::MissingNonceError(pk))
            })
            .collect::<Result<Vec<MusigPubNonce>, _>>()?;

        let key_pair = ZkpKeyPair::from_secret_key(secp, &privkey.to_zkp());

        let aggnonce = MusigAggNonce::new(secp, &sorted_nonces[..]);

        let sighash = taproot_sighash(psbt, input_index, self.core.tap_leaf)
            .map_err(|_| SignError::SighashError)?;

        let sighash_message = Message::from_digest_slice(sighash.as_ref())
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
    pub fn sign<C: ZkpSigning>(self, secp: &ZkpSecp256k1<C>, privkey: &SecretKey, psbt: &mut MusigPsbt, input_index: usize) -> Result<SignatureAggregateContext<'a>, SignError> {
        let psbt_key = self.core.psbt_key_with_pubkey(&self.pubkey);

        let (agg_context, partial_signature) = self.get_partial_signature(secp, privkey, psbt, input_index)?;

        let input = psbt.inputs
            .get_mut(input_index)
            .ok_or(SignError::InvalidInputIndexError)?;

        input.add_item(psbt_key, partial_signature)
            .map_err(|_| SignError::SerializeError)?;

        // FIXME: still janky
        let musig_input = psbt.musig_inputs.get_mut(input_index)
            .ok_or(SignError::InvalidInputIndexError)?;
        musig_input.partial_signature.insert(psbt_key, partial_signature);

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
    pub fn get_aggregate_signature<C: ZkpSigning>(self, secp: &ZkpSecp256k1<C>, psbt: &MusigPsbt, input_index: usize) -> Result<ZkpSchnorrSignature, SignatureAggregateError> {
        let (input, musig_input) = psbt.get_input(input_index)
            .ok_or(SignatureAggregateError::InvalidInputIndexError)?;

        let agg_pk_set = self.core.agg_pk_set();

        let partial_signatures: BTreeMap<PublicKey, MusigPartialSignature> = musig_input.partial_signature.iter()
            .filter_map(|((pk, agg_pk, tap_leaf), partial_signature)| {
                // FIXME: make sure we're using the right agg_pk in case of derivation
                // bip specifies this, I think it's the un-tweaked...
                if (*agg_pk, *tap_leaf) != (self.core.key_agg_pk.from_zkp(), self.core.tap_leaf) {
                    return None;
                }

                Some((pk.clone(), partial_signature.clone()))
            })
            .collect();

        let ordered_signatures = self.sort_and_validate_signatures(secp, &partial_signatures)?;

        Ok(self.session.partial_sig_agg(&ordered_signatures[..]))
    }

    /// Update a psbt input with a newly calculated aggregate signature
    pub fn aggregate_signatures<C: ZkpSigning>(self, secp: &ZkpSecp256k1<C>, psbt: &mut MusigPsbt, input_index: usize) -> Result<(), SignatureAggregateError> {
        let agg_pk = self.core.key_agg_pk.from_zkp();
        let xonly_agg_pk = agg_pk.x_only_public_key().0;
        let tap_leaf = self.core.tap_leaf;
        let signature = self.get_aggregate_signature(secp, psbt, input_index)?;

        let input = psbt.inputs
            .get_mut(input_index)
            .ok_or(SignatureAggregateError::InvalidInputIndexError)?;

        let sighash = input.taproot_hash_ty()
            .map_err(|_| SignatureAggregateError::IncompatibleSighashError)?;

        let schnorr_sig = Signature {
            sig: signature.from_zkp(),
            hash_ty: sighash,
        };

        if let Some(tap_leaf) = tap_leaf {
            // FIXME: make sure we're using the correct x-only agg_pk
            input.tap_script_sigs.insert((xonly_agg_pk, tap_leaf), schnorr_sig);
            todo!()
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

#[derive(Debug,Clone)]
pub enum OutpointsMapError {
    MissingUtxo,
    InvalidPrevoutIndex,
}

#[derive(Debug,Clone)]
pub enum VerifyError {
    VerificationFailed,
    OutpointsMapError(OutpointsMapError),
}

/// Helper to enable easier interaction with PSBTs
pub trait PsbtHelper {
    fn get_input_script_pubkey(&self, index: usize) -> Option<&Script>;

    fn finalize_key_spends(&mut self);

    fn outpoints_map(&self) -> Result<BTreeMap<OutPoint, TxOut>, OutpointsMapError>;

    #[cfg(feature="verify")]
    fn verify(&self) -> Result<(), VerifyError>;
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

            let previous_index = input.previous_output.vout as usize;
            let previous_output: &TxOut = previous_tx.output.get(previous_index)?;

            return Some(&previous_output.script_pubkey);
        }

        return None;
    }

    fn finalize_key_spends(&mut self) {
        for input in self.inputs.iter_mut() {
            input.finalize_key_spend();
        }
    }

    fn outpoints_map(&self) -> Result<BTreeMap<OutPoint, TxOut>, OutpointsMapError> {
        // Borrows pretty heavily from PartiallySignedTransaction::iter_funding_utxos
        // although it's admittedly *the* obvious approach
        self.unsigned_tx.input.iter()
            .zip(&self.inputs)
            .map(|(txin, input)| {
            match (&input.witness_utxo, &input.non_witness_utxo) {
                (Some(witness_utxo), _) => {
                    Ok((txin.previous_output, witness_utxo.clone()))
                },
                (None, Some(non_witness_utxo)) => {
                    let prevout_index = txin.previous_output.vout as usize;
                    non_witness_utxo.output.get(prevout_index)
                        .map(|txout| (txin.previous_output, txout.clone()))
                        .ok_or(OutpointsMapError::InvalidPrevoutIndex)
                },
                (None, None) => {
                    Err(OutpointsMapError::MissingUtxo)
                },
            }
            })
            .collect()
    }

    #[cfg(feature="verify")]
    fn verify(&self) -> Result<(), VerifyError> {
        let outpoints = self.outpoints_map()
            .map_err(|e| VerifyError::OutpointsMapError(e))?;

        let tx = self.clone().extract_tx();

        tx.verify(|outpoint| {
            outpoints.get(outpoint).map(|txout| txout.clone())
        })
        .map_err(|_e| VerifyError::VerificationFailed)
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

#[derive(Debug)]
/// Error updating a psbt input's musig keys or values
pub enum InputUpdateError {
    InvalidIndex,
    DeserializeError(DeserializeError),
}

pub trait PsbtInputUpdater {
    fn update_musig<F: MusigPsbtFilter>(&mut self, input: &PsbtInput, musig_input: &MusigPsbtInput, filter: F) -> Result<usize, DeserializeError>;
}

impl PsbtInputUpdater for MusigPsbtInput {
    fn update_musig<F: MusigPsbtFilter>(&mut self, input: &PsbtInput, musig_input: &MusigPsbtInput, filter: F) -> Result<usize, DeserializeError> {
        let mut updated = 0;

        for kv in musig_input.iter_musig_kvs() {
            if filter.filter_key(&kv) {
                match kv {
                    MusigPsbtKeyValue::Participants((k, v)) => { self.participants.insert(*k, v.clone()); }
                    MusigPsbtKeyValue::PublicNonce((k, v)) => { self.public_nonce.insert(*k, *v); }
                    MusigPsbtKeyValue::PartialSignature((k, v)) => { self.partial_signature.insert(*k, *v); }
                }
                updated += 1;
            }
        }

        Ok(updated)
    }
}

/// Helper to update PSBT with additional information
pub trait PsbtUpdater {
    fn add_spend_info<C: Verification>(&mut self, secp: &Secp256k1<C>, context: &CoreContext, tap_script_pubkey: &TaprootScriptPubkey) -> Result<Vec<(usize, SpendInfoAddResult)>, SpendInfoAddError>;

    fn add_input_spend_info<C: Verification>(&mut self, secp: &Secp256k1<C>, context: &CoreContext, tap_script_pubkey: &TaprootScriptPubkey, index: usize) -> Result<SpendInfoAddResult, SpendInfoAddError>;

    fn add_participants<C: Verification>(&mut self, secp: &Secp256k1<C>, context: &CoreContext, tap_script_pubkey: &TaprootScriptPubkey) -> Result<Vec<(usize, ParticipantsAddResult)>, ParticipantsAddError>;

    fn add_input_participants<C: Verification>(&mut self, secp: &Secp256k1<C>, context: &CoreContext, tap_script_pubkey: &TaprootScriptPubkey, index: usize) -> Result<ParticipantsAddResult, ParticipantsAddError>;
}

impl PsbtUpdater for PartiallySignedTransaction {
    fn add_spend_info<C: Verification>(&mut self, secp: &Secp256k1<C>, context: &CoreContext, tap_script_pubkey: &TaprootScriptPubkey) -> Result<Vec<(usize, SpendInfoAddResult)>, SpendInfoAddError> {
        let mut result: Vec<_> = Vec::new();
        let input_len = self.inputs.len();

        for index in 0..input_len {
            let input_result = self.add_input_spend_info(secp, context, tap_script_pubkey, index)?;

            result.push((index, input_result));
        }

        Ok(result)
    }

    fn add_input_spend_info<C: Verification>(&mut self, secp: &Secp256k1<C>, context: &CoreContext, tap_script_pubkey: &TaprootScriptPubkey, index: usize) -> Result<SpendInfoAddResult, SpendInfoAddError> {
        let script_pubkey = self.get_input_script_pubkey(index)
            .ok_or(SpendInfoAddError::NoScriptPubkey)?
            .to_owned();

        let input = self.inputs.get_mut(index)
            .ok_or(SpendInfoAddError::InvalidIndex)?;

        if script_pubkey.clone() != tap_script_pubkey.script_pubkey(secp) {
            return Ok(SpendInfoAddResult::InputNoMatch);
        }

        let mut internal_key_modified = false;
        let mut merkle_root_modified = false;

        let tap_internal_key = Some(&tap_script_pubkey.internal_key);

        if input.tap_internal_key.as_ref() != tap_internal_key {
            input.tap_internal_key = tap_internal_key.copied();
            internal_key_modified = true;
        }

        if input.tap_merkle_root != tap_script_pubkey.merkle_root {
            input.tap_merkle_root = tap_script_pubkey.merkle_root;
            merkle_root_modified = true;
        }

        Ok(SpendInfoAddResult::Success {
            internal_key_modified,
            merkle_root_modified,
        })
    }

    fn add_participants<C: Verification>(&mut self, secp: &Secp256k1<C>, context: &CoreContext, tap_script_pubkey: &TaprootScriptPubkey) -> Result<Vec<(usize, ParticipantsAddResult)>, ParticipantsAddError> {
        let mut result: Vec<_> = Vec::new();
        let input_len = self.inputs.len();

        for index in 0..input_len {
            let input_result = self.add_input_participants(secp, context, tap_script_pubkey, index)?;

            result.push((index, input_result));
        }

        Ok(result)
    }

    fn add_input_participants<C: Verification>(&mut self, secp: &Secp256k1<C>, context: &CoreContext, tap_script_pubkey: &TaprootScriptPubkey, index: usize) -> Result<ParticipantsAddResult, ParticipantsAddError> {
        let script_pubkey = self.get_input_script_pubkey(index)
            .ok_or(ParticipantsAddError::NoScriptPubkey)?
            .to_owned();

        let input = self.inputs.get_mut(index)
            .ok_or(ParticipantsAddError::InvalidIndex)?;

        if script_pubkey.clone() != tap_script_pubkey.script_pubkey(secp) {
            return Ok(ParticipantsAddResult::InputNoMatch);
        }

        input.add_participants(context.key_agg_pk.from_zkp(), context.participant_pubkeys.as_ref())
            .map_err(|_| ParticipantsAddError::SerializeError)?;

        Ok(ParticipantsAddResult::ParticipantsAdded)
    }
}

pub trait MusigPsbtFilter {
    fn filter_key<'a>(&self, kv: &MusigPsbtKeyValue<'a>) -> bool;
}

impl<T: Fn(&MusigPsbtKeyValue) -> bool> MusigPsbtFilter for T {
    fn filter_key<'a>(&self, kv: &MusigPsbtKeyValue<'a>) -> bool
    {
        self(kv)
    }
}

struct FilterEntry {
    /// Match Musig Public Nonces
    nonces: bool,

    /// Match Musig Partial Signatures
    signatures: bool,

    /// Match Musig Participants
    participants: bool,

    /// The aggregate public key match
    agg_pk: Option<PublicKey>,

    /// The subset of participant public keys to match
    pubkeys: HashSet<PublicKey>,
}

impl MusigPsbtFilter for FilterEntry {
    fn filter_key<'a>(&self, kv: &MusigPsbtKeyValue<'a>) -> bool
    {
        let type_matches = match kv {
            MusigPsbtKeyValue::Participants(_) => self.participants,
            MusigPsbtKeyValue::PublicNonce(_) => self.nonces,
            MusigPsbtKeyValue::PartialSignature(_) => self.signatures,
        };

        if !type_matches {
            return false;
        }

        if let Some(ref agg_pk) = self.agg_pk {
            if agg_pk != kv.get_agg_pk() {
                return false;
            }
        }

        if !self.pubkeys.is_empty() {
            let pubkey_matches = match kv {
                MusigPsbtKeyValue::Participants((_agg_pk, participants)) => {
                    // TODO: review, is this really our desired behavior? probably not imho, any()
                    // probably makes more sense. Could also just make it be up to the caller, have
                    // two bundles of pubkeys
                    participants.iter().all(|pk| self.pubkeys.contains(pk))
                }
                MusigPsbtKeyValue::PublicNonce(((pk, agg_pk, _), _)) => self.pubkeys.contains(pk),
                MusigPsbtKeyValue::PartialSignature(((pk, agg_pk, _), _)) => self.pubkeys.contains(pk),
            };

            if !pubkey_matches {
                return false;
            }
        }

        return true;
    }
}

#[derive(Clone)]
struct ParticipantInfo {
    agg_xpub: ExtendedPubKey,
    tap_leaf: Option<TapLeafHash>,
    master_fingerprint: Fingerprint,
    xpub_path: DerivationPath,
    xpub: ExtendedPubKey,
    remaining_derivation: DerivationPath,
}

fn common_prefix(a: &DerivationPath, b: &DerivationPath) -> DerivationPath {
    a.as_ref().iter()
        .zip(b.as_ref().iter())
        .take_while(|(a, b)| a == b)
        .map(|(a, _b)| *a)
        .collect()
}

pub struct FindParticipatingExtendedKeys {
    keys: HashMap<Fingerprint, (ExtendedPubKey, DerivationPath)>,
}

impl FindParticipatingExtendedKeys {
    pub fn from_global_xpubs<'a, I: Iterator<Item=(&'a Fingerprint, &'a ExtendedPubKey, &'a DerivationPath)>, C: Verification>(secp: &Secp256k1<C>, known_xprivs: I, psbt: &PartiallySignedTransaction) -> Self {
        let mut known_xprivs: Vec<(Fingerprint, ExtendedPubKey, DerivationPath, usize)> = known_xprivs
            .map(|(fingerprint, xpub, derivation_path)| {
                psbt.xpub.iter()
                    .filter_map(move |(found_xpub, (found_fingerprint, found_derivation_path))| {
                        if found_fingerprint != fingerprint {
                            return None;
                        }

                        let prefix_path = common_prefix(&derivation_path, &found_derivation_path);
                        if prefix_path.len() != derivation_path.len() {
                            return None;
                        }

                        let remaining_derivation: DerivationPath =
                            derivation_path.as_ref().iter()
                                .skip(prefix_path.len())
                                .cloned()
                                .collect();

                        let derived_xpub = found_xpub.derive_pub(secp, &remaining_derivation)
                            .ok()?;

                        if derived_xpub == *found_xpub {
                            Some(
                                (fingerprint.clone(), xpub.clone(), derivation_path.clone(), remaining_derivation.len())
                            )
                        } else {
                            None
                        }
                    })
            })
            .flatten()
            .collect();

        known_xprivs.sort_by_key(|(_fingerprint, _xpub, _derivation_path, remaining_path_length)| *remaining_path_length);

        let known_xprivs = known_xprivs.into_iter()
            .map(|(fingerprint, xpub, derivation_path, _remaining_path_length)| (fingerprint, (xpub, derivation_path)));

        Self {
            keys: HashMap::from_iter(known_xprivs),
        }
    }

    fn iter_participating<'a, 'secp, 'psbt, C: Verification>(&'a self, secp: &'secp Secp256k1<C>, input: &'psbt PsbtInput, musig_input: &'psbt MusigPsbtInput) -> impl Iterator<Item=(ParticipantInfo, DerivationPath)> + 'a
    where
        'secp: 'a,
        'psbt: 'a,
    {
        // FIXME: clean up this mess... somehow...
        input.tap_key_origins.iter()
            // enumerate all possible tap derivations, including the key path
            // The caller will need to filter the key path if it is not desired.
            .map(|(pubkey, (tap_leaves, (fingerprint, derivation)))| {
                tap_leaves.iter()
                    .map(move |tap_leaf| (pubkey, Some(tap_leaf), fingerprint, derivation))
                    .chain(once((pubkey, None, fingerprint, derivation)))
            })
            .flatten()
            // filter out tap derivations that don't match a key fingerprint we know
            // filter out tap derivations where the derived key doesn't match the expected value
            // (ignoring parity, since it is not represented in tap derivations)
            // filter out tap derivations where the derived key does not participate in a musig
            // aggregate key
            // filter out tap derivations where the aggregate key is not used
            //
            .filter_map(move |(found_derived_pubkey, tap_leaf, fingerprint, derivation)| {
                self.keys.get(fingerprint)
                    .and_then(move |(xpub, xpub_path)| {
                        let prefix_path = common_prefix(&xpub_path, &derivation);

                        // Check if the derivation path is equal to or derived from this known xpub
                        if prefix_path.len() != xpub_path.len() {
                            return None;
                        }

                        let remaining_derivation: DerivationPath =
                            derivation.as_ref().iter()
                                .skip(prefix_path.len())
                                .cloned()
                                .collect();

                        let derived_xpub = xpub.derive_pub(secp, &remaining_derivation)
                            .ok()?;

                        let derived_pubkey = derived_xpub.to_pub().inner;

                        let (parity_insensitive_pk, _parity) = derived_pubkey.x_only_public_key();

                        // check if derived pubkey matches
                        if *found_derived_pubkey != parity_insensitive_pk {
                            return None;
                        }

                        Some((fingerprint, xpub, xpub_path, remaining_derivation, derived_pubkey, tap_leaf))
                    })
            })
            // generate a participation context for
            // derived keys that participate in a musig signing
            .map(move |(fingerprint, xpub, xpub_path, remaining_derivation, derived_pubkey, tap_leaf)| {
                musig_input.participants.iter()
                    .filter_map(move |(agg_pk, pubkeys)| {
                        if pubkeys.contains(&derived_pubkey) {
                            // TODO: I think we could eliminate several copies
                            // throughout this code by returning references
                            Some(ParticipantInfo {
                                // FIXME: don't hard code network
                                agg_xpub: musig_agg_pk_to_xpub(agg_pk.to_owned(), Network::Bitcoin),
                                tap_leaf: tap_leaf.copied(),
                                master_fingerprint: fingerprint.to_owned(),
                                xpub_path: xpub_path.to_owned(),
                                xpub: xpub.to_owned(),
                                remaining_derivation: remaining_derivation.clone(),
                            })
                        } else {
                            None
                        }
                    })
            })
            .flatten()
            // Find matching derivations from the agg_pk
            .map(move |participation| {
                input.tap_key_origins.iter()
                    // FIXME: should we do this for every leaf hash in leaf_hashes regardless of
                    // the participant key leaf hashes?
                    .filter_map(move |(found_agg_pk, (leaf_hashes, (new_fingerprint, agg_pk_derivation)))| {
                        // Check that the fingerprint matches
                        if *new_fingerprint != participation.agg_xpub.fingerprint() {
                            return None;
                        }

                        let leaf_matches = participation.tap_leaf
                            .map(|tap_leaf| leaf_hashes.contains(&tap_leaf))
                            // Always match the key path
                            .unwrap_or(true);

                        // Check if this derivation info matches our tap leaf
                        // If we are currently doing the key path always match
                        if !leaf_matches {
                            return None;
                        }

                        let (parity_insensitive_agg_pk, _parity) =
                            participation.agg_xpub
                            .derive_pub(secp, agg_pk_derivation)
                            .ok()?
                            .public_key
                            .x_only_public_key();

                        // Check if this derived key matches our agg pk
                        if *found_agg_pk != parity_insensitive_agg_pk {
                            return None;
                        }

                        let matches_internal_key = input.tap_internal_key
                            .map(|ik| ik == parity_insensitive_agg_pk)
                            .unwrap_or(true);

                        // If internal key info is present, ensure this
                        // aggregate key matches
                        // XXX: If the internal key info is not present, we
                        // treat it as a match, this might be undesirable,
                        // revisit this decision
                        if participation.tap_leaf.is_none() && !matches_internal_key {
                            return None;
                        }

                        Some((participation.clone(), agg_pk_derivation.clone()))
                    })
            })
            .flatten()
    }
}

impl FromIterator<(Fingerprint, (ExtendedPubKey, DerivationPath))> for FindParticipatingExtendedKeys {
    fn from_iter<T: IntoIterator<Item=(Fingerprint, (ExtendedPubKey, DerivationPath))>>(iter: T) -> Self {
        Self { keys: FromIterator::from_iter(iter) }
    }
}

pub struct FindParticipatingKeys {
    keys: HashSet<PublicKey>,
}

impl FindParticipatingKeys {
    pub fn new(keys: HashSet<PublicKey>) -> Self {
        Self { keys }
    }

    pub fn from_key(key: PublicKey) -> Self {
        Self::from_iter(once(key))
    }

    fn iter_participating<'a, 'secp, 'psbt, C: Verification>(&'a self, secp: &'secp Secp256k1<C>, input: &'psbt PsbtInput, musig_input: &'psbt MusigPsbtInput) -> impl Iterator<Item=(Vec<PublicKey>, PublicKey, Option<TapLeafHash>, DerivationPath)> + 'a
    where
        'secp: 'a,
        'psbt: 'a,
    {
        musig_input.participants.iter()
            .flat_map(move |(agg_pk, pubkeys)| {
                pubkeys.iter()
                    .filter_map(move |participating_pubkey| {
                        if self.keys.contains(participating_pubkey) {
                            Some((agg_pk, pubkeys, participating_pubkey))
                        } else {
                            None
                        }
                    })
            })
            // Find matching derivations from the agg_pk
            .flat_map(move |(agg_pk, pubkeys, participating_pubkey)| {
                input.tap_key_origins.iter()
                    .flat_map(move |(found_agg_pk, (leaf_hashes, (new_fingerprint, agg_pk_derivation)))| {

                        leaf_hashes.iter()
                            .map(|leaf_hash| Some(leaf_hash))
                            .chain(once(None)) // Include key path
                            .filter_map(move |leaf_hash| {
                                // FIXME: don't hard code network
                                let agg_xpub = musig_agg_pk_to_xpub(agg_pk.clone(), Network::Bitcoin);

                                // Check that the fingerprint matches
                                if *new_fingerprint != agg_xpub.fingerprint() {
                                    return None;
                                }

                                let (parity_insensitive_agg_pk, _parity) = agg_xpub
                                    .derive_pub(secp, agg_pk_derivation)
                                    .ok()?
                                    .public_key
                                    .x_only_public_key();

                                // Check if this derived key matches our agg pk
                                if *found_agg_pk != parity_insensitive_agg_pk {
                                    return None;
                                }

                                let matches_internal_key = input.tap_internal_key
                                    .map(|ik| ik == parity_insensitive_agg_pk)
                                    .unwrap_or(true);

                                // TODO: I think we can return references if we play our lifetimes
                                // right
                                // FIXME: correct?
                                if matches_internal_key {
                                    Some((pubkeys.clone(), participating_pubkey.clone(), leaf_hash.cloned(), agg_pk_derivation.clone()))
                                } else {
                                    None
                                }
                            })
                    })
            })
    }

    pub fn iter_participating_input_context<'a, 'secp, C: Verification, ZC: ZkpVerification>(&'a self, secp: &'secp Secp256k1<C>, zkp_secp: &'secp ZkpSecp256k1<ZC>, input: &'a PsbtInput, musig_input: &'a MusigPsbtInput) -> impl Iterator<Item=Result<(PublicKey, CoreContext), CoreContextCreateError>> + 'a
    where
        'secp: 'a,
    {
        self.iter_participating(secp, input, musig_input)
            .map(move |(pubkeys, participating_pubkey, tap_leaf, derivation)|
                CoreContext::from_input(zkp_secp, input, pubkeys.clone(), tap_leaf.clone(), &derivation)
                        .map(|context| (participating_pubkey, context))
            )
    }

    pub fn iter_participating_context<'a, 'secp, 'r, C: Verification, ZC: ZkpVerification>(&'a self, secp: &'secp Secp256k1<C>, zkp_secp: &'secp ZkpSecp256k1<ZC>, psbt: &'r MusigPsbt) -> impl Iterator<Item=(usize, Result<(PublicKey, CoreContext), CoreContextCreateError>)> + 'r
    where
        'secp: 'r,
        'a: 'r,
    {
        psbt.iter_musig_inputs()
            .enumerate()
            .map(move |(index, (musig_input, input))| {
                self.iter_participating_input_context(secp, zkp_secp, musig_input, input)
                    .map(move |result| (index, result))
            })
            .flatten()
    }
}

impl FromIterator<PublicKey> for FindParticipatingKeys {
    fn from_iter<T: IntoIterator<Item=PublicKey>>(iter: T) -> Self {
        Self { keys: FromIterator::from_iter(iter) }
    }
}
