use bitcoin::VarInt;

use bitcoin::consensus::encode::{
    Decodable,
    Encodable,
};

use bitcoin::psbt::{
    Input as PsbtInput,
    raw::Key as PsbtKey,
    PartiallySignedTransaction,
};

use bitcoin::secp256k1::{
    PublicKey,
    constants::PUBLIC_KEY_SIZE,
};

use bitcoin::bip32::{
    ChildNumber,
    KeySource,
};

use bitcoin::taproot::TapLeafHash;

use secp256k1_zkp::{
    MusigPartialSignature,
    MusigPubNonce,
    ffi::MUSIG_PUBNONCE_SERIALIZED_LEN,
};

use std::collections::BTreeMap;

use std::io::{
    Cursor,
    Error as IoError,
    ErrorKind as IoErrorKind,
    Read,
    Write,
};

use std::mem::size_of;

use std::ops::{
    Deref,
    DerefMut,
};

use crate::{
    MusigPsbtFilter,
    psbt::PsbtInputUpdater,
};

const MUSIG_PARTIAL_SIGNATURE_SERIALIZED_LEN: usize = 32;

// FIXME: psbt key types are actually var ints, once rust-bitcoin updates, update here
/// The type of psbt keys
pub type PsbtKeyType = u8;

/// The type of the index of a participant in an aggregate signing
pub type ParticipantIndex = u32;

pub const PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS: PsbtKeyType = 0x1a;
pub const PSBT_IN_MUSIG2_PUB_NONCE: PsbtKeyType = 0x1b;
pub const PSBT_IN_MUSIG2_PARTIAL_SIG: PsbtKeyType = 0x1c;

/// Newtype which is always serialized as a sequence of fixed-length items
/// which ends when the end of the Reader is reached
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct VariableLengthArray<T>(pub Vec<T>);

pub type ParticipantPubkeysKey = PublicKey;
pub type ParticipantPubkeysValue = VariableLengthArray<PublicKey>;
pub type ParticipantPubkeysKeyValue = (ParticipantPubkeysKey, ParticipantPubkeysValue);

// XXX: .1 is the agg pk
type SigningDataKey = (PublicKey, PublicKey, Option<TapLeafHash>);

pub type PublicNonceKey = SigningDataKey;
pub type PublicNonceValue = MusigPubNonce;
pub type PublicNonceKeyValue = (PublicNonceKey, PublicNonceValue);

pub type PartialSignatureKey = SigningDataKey;
pub type PartialSignatureValue = MusigPartialSignature;
pub type PartialSignatureKeyValue = (PartialSignatureKey, PartialSignatureValue);

#[derive(Debug)]
/// Error when serializing to a PSBT value
pub enum SerializeError {
    IoError(IoError),
    SerializeError,
    SerializeElementError(usize),
}

#[derive(Debug)]
/// Error when deserializing a PSBT value
pub enum DeserializeError {
    IoError(IoError),
    DeserializeError,
    DeserializeElementError(usize),
}

#[derive(Debug)]
/// Error when deserializing or deserializing a PSBT value
pub enum SerializeOrDeserializeError {
    SerializeError(SerializeError),
    DeserializeError(DeserializeError),
}

impl From<SerializeError> for SerializeOrDeserializeError {
    fn from(e: SerializeError) -> Self {
        SerializeOrDeserializeError::SerializeError(e)
    }
}

impl From<DeserializeError> for SerializeOrDeserializeError {
    fn from(e: DeserializeError) -> Self {
        SerializeOrDeserializeError::DeserializeError(e)
    }
}

/// Trait which permits deserializing from Readers and serializing to Writers
pub trait PsbtValue
    where Self: Sized
{
    fn serialize<W: Write>(&self, writer: &mut W) -> Result<(), SerializeError>;
    fn deserialize<R: Read>(reader: &mut R) -> Result<Self, DeserializeError>;
}

// Using this marker to whitelist types, otherwise adding new Encode/Decode
// impls in rust-bitcoin could cause a conflict
trait ConsensusImpl {}

impl ConsensusImpl for ParticipantIndex {}
impl ConsensusImpl for VarInt {}
impl ConsensusImpl for TapLeafHash {}

impl<T> PsbtValue for T
    where
        T: Encodable + Decodable + ConsensusImpl,
{
    fn serialize<W: Write>(&self, writer: &mut W) -> Result<(), SerializeError> {
        self.consensus_encode(writer)
            .map_err(|_| SerializeError::SerializeError)?;

        Ok(())
    }

    fn deserialize<R: Read>(reader: &mut R) -> Result<Self, DeserializeError> {
        let result = Self::consensus_decode(reader)
            .map_err(|_| DeserializeError::DeserializeError)?;

        Ok(result)
    }
}

impl<A, B> PsbtValue for (A, B)
    where
        A: PsbtValue,
        B: PsbtValue,
{
    fn serialize<W: Write>(&self, writer: &mut W) -> Result<(), SerializeError> {
        self.0.serialize(writer)?;
        self.1.serialize(writer)?;

        Ok(())
    }

    fn deserialize<R: Read>(reader: &mut R) -> Result<Self, DeserializeError> {
        let a = A::deserialize(reader)?;
        let b = B::deserialize(reader)?;

        Ok((a, b))
    }
}

trait KnownSize {
    const SIZE: usize;
}

impl KnownSize for PublicKey {
    const SIZE: usize = PUBLIC_KEY_SIZE;
}

impl KnownSize for TapLeafHash {
    const SIZE: usize = 32;
}

impl<T> PsbtValue for Option<T>
    where
        T: PsbtValue + KnownSize,
{
    fn serialize<W: Write>(&self, writer: &mut W) -> Result<(), SerializeError> {
        if let Some(ref inner) = self {
            inner.serialize(writer)?;
        }

        Ok(())
    }

    fn deserialize<R: Read>(reader: &mut R) -> Result<Self, DeserializeError> {
        let mut buf = vec![0u8; T::SIZE];

        let result = read_all_or_nothing(reader, &mut buf[..])
            .map_err(|_e| DeserializeError::DeserializeError)?;

        // XXX: Messy
        match result.map(|_| T::deserialize(&mut Cursor::new(&buf))) {
            Some(x) => { Ok(Some(x?)) },
            None => Ok(None)
        }
    }
}

impl<T> PsbtValue for VariableLengthArray<T>
    where
        T: PsbtValue + KnownSize,
{
    fn serialize<W: Write>(&self, writer: &mut W) -> Result<(), SerializeError> {
        for item in self.0.iter() {
            item.serialize(writer)?;
        }

        Ok(())
    }

    fn deserialize<R: Read>(reader: &mut R) -> Result<Self, DeserializeError> {
        let mut result: Vec<T> = Vec::new();
        let mut buf = vec![0u8; T::SIZE];

        loop {
            let read_result = read_all_or_nothing(reader, &mut buf[..])
                .map_err(|_e| DeserializeError::DeserializeError)?;

            if read_result.is_none() {
                break;
            }

            let item = T::deserialize(&mut Cursor::new(&buf))?;
            result.push(item);
        }

        Ok(Self(result))
    }
}

impl<A, B, C> PsbtValue for (A, B, C)
    where
        A: PsbtValue,
        B: PsbtValue,
        C: PsbtValue,
{
    fn serialize<W: Write>(&self, writer: &mut W) -> Result<(), SerializeError> {
        self.0.serialize(writer)?;
        self.1.serialize(writer)?;
        self.2.serialize(writer)?;

        Ok(())
    }

    fn deserialize<R: Read>(reader: &mut R) -> Result<Self, DeserializeError> {
        let a = A::deserialize(reader)?;
        let b = B::deserialize(reader)?;
        let c = C::deserialize(reader)?;

        Ok((a, b, c))
    }
}

impl<T> PsbtValue for Vec<T>
    where
        T: PsbtValue
{
    fn serialize<W: Write>(&self, writer: &mut W) -> Result<(), SerializeError> {
        let len = VarInt(self.len() as u64);

        len.serialize(writer)?;

        for x in self.iter() {
            x.serialize(writer)?;
        }

        Ok(())
    }

    fn deserialize<R: Read>(reader: &mut R) -> Result<Self, DeserializeError> {
        let len = VarInt::deserialize(reader)?;

        let mut result: Vec<T> = Vec::with_capacity(len.0 as usize);

        for _i in 0..len.0 {
            result.push(T::deserialize(reader)?);
        }

        Ok(result)
    }
}

impl PsbtValue for PublicKey {
    fn serialize<W: Write>(&self, writer: &mut W) -> Result<(), SerializeError> {
        let pubkey_bytes = self.serialize();

        writer.write_all(&pubkey_bytes)
            .map_err(|e| SerializeError::IoError(e))?;

        Ok(())
    }

    fn deserialize<R: Read>(reader: &mut R) -> Result<Self, DeserializeError> {
        let mut pubkey_bytes = [0u8; PUBLIC_KEY_SIZE];
        reader.read_exact(&mut pubkey_bytes)
            .map_err(|e| DeserializeError::IoError(e))?;

        let pubkey = PublicKey::from_slice(&pubkey_bytes)
            .map_err(|_| DeserializeError::DeserializeError)?;

        Ok(pubkey)
    }
}

impl PsbtValue for MusigPubNonce {
    fn serialize<W: Write>(&self, writer: &mut W) -> Result<(), SerializeError> {
        let pubnonce_bytes = self.serialize();

        writer.write_all(&pubnonce_bytes)
            .map_err(|e| SerializeError::IoError(e))?;

        Ok(())
    }

    fn deserialize<R: Read>(reader: &mut R) -> Result<Self, DeserializeError> {
        let mut pubnonce_bytes = [0u8; MUSIG_PUBNONCE_SERIALIZED_LEN];
        reader.read_exact(&mut pubnonce_bytes)
            .map_err(|e| DeserializeError::IoError(e))?;

        let pubnonce = MusigPubNonce::from_slice(&pubnonce_bytes)
            .map_err(|_| DeserializeError::DeserializeError)?;

        Ok(pubnonce)
    }
}

impl PsbtValue for MusigPartialSignature {
    fn serialize<W: Write>(&self, writer: &mut W) -> Result<(), SerializeError> {
        let partial_signature_bytes = self.serialize();

        writer.write_all(&partial_signature_bytes)
            .map_err(|e| SerializeError::IoError(e))?;

        Ok(())
    }

    fn deserialize<R: Read>(reader: &mut R) -> Result<Self, DeserializeError> {
        let mut partial_signature_bytes = [0u8; MUSIG_PARTIAL_SIGNATURE_SERIALIZED_LEN];
        reader.read_exact(&mut partial_signature_bytes)
            .map_err(|e| DeserializeError::IoError(e))?;

        let partial_signature = MusigPartialSignature::from_slice(&partial_signature_bytes)
            .map_err(|_| DeserializeError::DeserializeError)?;

        Ok(partial_signature)
    }
}

impl PsbtValue for KeySource {
    fn serialize<W: Write>(&self, writer: &mut W) -> Result<(), SerializeError> {
        writer.write_all(self.0.as_bytes())
            .map_err(|e| SerializeError::IoError(e))?;

        for &child_number in self.1.as_ref() {
            let path_element: u32 = child_number.into();
            let path_element_bytes = path_element.to_le_bytes();
            writer.write_all(&path_element_bytes)
                .map_err(|e| SerializeError::IoError(e))?;
        }

        Ok(())
    }

    fn deserialize<R: Read>(reader: &mut R) -> Result<Self, DeserializeError> {
        let mut fingerprint = [0u8; 4];
        reader.read_exact(&mut fingerprint)
            .map_err(|e| DeserializeError::IoError(e))?;

        let mut path = Vec::<ChildNumber>::new();

        loop {
            let mut path_element_buf = [0u8; size_of::<u32>()];
            match read_all_or_nothing(reader, &mut path_element_buf) {
                Ok(None) => {
                    break;
                },
                Ok(Some(_)) => {
                    let path_element = u32::from_le_bytes(path_element_buf);
                    path.push(path_element.into());
                },
                Err(e) => {
                    return Err(DeserializeError::IoError(e));
                }
            }
        }

        Ok((fingerprint.into(), path.into()))
    }
}

/// Trait mapping PSBT key/value types to a PSBT key type
pub trait PsbtKeyValue {
    const KEY_TYPE: PsbtKeyType;
}

impl PsbtKeyValue for ParticipantPubkeysKeyValue {
    const KEY_TYPE: PsbtKeyType = PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS;
}

impl PsbtKeyValue for PublicNonceKeyValue {
    const KEY_TYPE: PsbtKeyType = PSBT_IN_MUSIG2_PUB_NONCE;
}

impl PsbtKeyValue for PartialSignatureKeyValue {
    const KEY_TYPE: PsbtKeyType = PSBT_IN_MUSIG2_PARTIAL_SIG;
}

fn read_all_or_nothing<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<Option<()>, IoError> {
    loop {
        match reader.read(buf) {
            Ok(0) => {
                return Ok(None);
            },
            Ok(n) => {
                return Ok(Some(reader.read_exact(&mut buf[n..])?));
            },
            Err(e) => {
                if e.kind() != IoErrorKind::Interrupted {
                    return Err(e);
                }
            },
        }
    }
}

/// Trait for deserializing from a PSBT key/value pair
pub trait ToPsbtKeyValue: Sized {
    fn to_psbt(&self) -> Result<(PsbtKey, Vec<u8>), SerializeError>;
}

impl<K: PsbtValue, V: PsbtValue> ToPsbtKeyValue for (K, V)
    where (K, V): PsbtKeyValue
{
    fn to_psbt(&self) -> Result<(PsbtKey, Vec<u8>), SerializeError> {
        let mut key_buf = Vec::<u8>::new();
        self.0.serialize(&mut key_buf)?;

        let mut value_buf = Vec::<u8>::new();
        PsbtValue::serialize(&self.1, &mut value_buf)?;

        Ok((PsbtKey {
            type_value: Self::KEY_TYPE as PsbtKeyType,
            key: key_buf,
        }, value_buf))
    }
}

/// Extra functionality for psbt input proprietary key/value pairs
pub trait MusigPsbtInputSerializer {
    /// Serialize and add a key/value pair
    fn add_item<K: PsbtValue, V: PsbtValue> (&mut self, key: K, value: V) -> Result<(), SerializeError>
        where (K, V): PsbtKeyValue;

    fn add_participants(&mut self, agg_pk: PublicKey, pubkeys: &[PublicKey]) -> Result<(), SerializeError> {
        self.add_item(agg_pk, VariableLengthArray(pubkeys.to_vec()))
    }

    fn add_nonce(&mut self, pubkey: PublicKey, agg_pk: PublicKey, tap_leaf: Option<TapLeafHash>, nonce: MusigPubNonce) -> Result<(), SerializeError> {
        self.add_item((pubkey, agg_pk, tap_leaf), nonce)
    }

    fn add_partial_signature(&mut self, pubkey: PublicKey, agg_pk: PublicKey, tap_leaf: Option<TapLeafHash>, sig: MusigPartialSignature) -> Result<(), SerializeError> {
        self.add_item((pubkey, agg_pk, tap_leaf), sig)
    }
}

/// Extra functionality for psbt input proprietary key/value pairs
impl MusigPsbtInputSerializer for PsbtInput {
    fn add_item<K: PsbtValue, V: PsbtValue>(&mut self, key: K, value: V) -> Result<(), SerializeError>
        where (K, V): PsbtKeyValue
    {
        let (ser_key, ser_value) = (key, value).to_psbt()?;

        // FIXME: handle case where key is already present, is that an error? Probably not, since
        // any third party tampering could add a conflicting key to trigger an error, and any third
        // party could remove this key to give the appearance it is not present.
        // The signer cannot rely on the psbt to contain data containing state.
        // Out of scope but maybe the psbt *could* contain a required, authenticated, encrypted chunk of data, which could contain such information.

        self.unknown
            .insert(ser_key, ser_value);

        Ok(())
    }
}

#[derive(Clone)]
pub struct MusigPsbt {
    pub psbt: PartiallySignedTransaction,
    pub musig_inputs: Vec<MusigPsbtInput>,
}

impl Deref for MusigPsbt {
    type Target = PartiallySignedTransaction;

    fn deref(&self) -> &Self::Target {
        &self.psbt
    }
}

impl DerefMut for MusigPsbt {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.psbt
    }
}

impl MusigPsbt {
    pub fn from_psbt(psbt: PartiallySignedTransaction) -> Result<MusigPsbt, DeserializeError> {
        let musig_inputs = psbt.inputs.iter()
            .map(|input| MusigPsbtInput::from_input(input))
            .collect::<Result<_, _>>()?;

        Ok(Self {
            psbt,
            musig_inputs,
        })
    }

    pub fn get_input(&self, index: usize) -> Option<(&PsbtInput, &MusigPsbtInput)> {
        match (self.psbt.inputs.get(index), self.musig_inputs.get(index)) {
            (Some(input), Some(musig_input)) => Some((input, musig_input)),
            (None, None) => None,
            _ => {
                // FIXME: is this too extreme?
                panic!("MusigPsbt inconsistent data");
            }
        }
    }

    pub fn iter_musig_inputs(&self) -> impl Iterator<Item = (&PsbtInput, &MusigPsbtInput)> {
        self.inputs.iter().zip(self.musig_inputs.iter())
    }

    pub fn iter_musig_inputs_mut(&mut self) -> impl Iterator<Item = (&PsbtInput, &mut MusigPsbtInput)> {
        self.psbt.inputs.iter().zip(self.musig_inputs.iter_mut())
    }

    pub fn update_musig<F: MusigPsbtFilter + Copy>(&mut self, other: &MusigPsbt, filter: F) -> Result<usize, DeserializeError> {
        let results = self.musig_inputs.iter_mut()
            .zip(other.psbt.inputs.iter().zip(other.musig_inputs.iter()))
            .map(|(musig_input, (other_input, other_musig_input))| {
                musig_input.update_musig(other_input, other_musig_input, filter)
            });

        // FIXME: is there a better way to sum a fallible iterator?
        let mut sum: usize = 0;
        for result in results {
            sum += result?;
        }

        Ok(sum)
    }

    pub fn into_psbt(self) -> Result<PartiallySignedTransaction, SerializeError> {
        let mut psbt = self.psbt;

        for (input, musig_input) in psbt.inputs.iter_mut().zip(self.musig_inputs) {
            musig_input.serialize_into_input(input)?;
        }

        Ok(psbt)
    }
}

#[derive(Clone)]
pub struct MusigPsbtInput {
    pub participants: BTreeMap<ParticipantPubkeysKey, Vec<PublicKey>>,
    pub public_nonce: BTreeMap<PublicNonceKey, PublicNonceValue>,
    pub partial_signature: BTreeMap<PartialSignatureKey, PartialSignatureValue>,
}

impl MusigPsbtInput {
    pub fn from_input(input: &PsbtInput) -> Result<MusigPsbtInput, DeserializeError> {
        let mut participants: BTreeMap<ParticipantPubkeysKey, Vec<PublicKey>> = BTreeMap::new();
        let mut public_nonce: BTreeMap<PublicNonceKey, PublicNonceValue> = BTreeMap::new();
        let mut partial_signature: BTreeMap<PartialSignatureKey, PartialSignatureValue> = BTreeMap::new();

        for (key, value) in input.unknown.iter() {
            match key.type_value {
                PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS => {
                    let key = ParticipantPubkeysKey::deserialize(&mut Cursor::new(&key.key))?;
                    let value = ParticipantPubkeysValue::deserialize(&mut Cursor::new(value))?;
                    participants.insert(key, value.0);
                }
                PSBT_IN_MUSIG2_PUB_NONCE => {
                    let key = PublicNonceKey::deserialize(&mut Cursor::new(&key.key))?;
                    let value = PublicNonceValue::deserialize(&mut Cursor::new(value))?;
                    public_nonce.insert(key, value);
                }
                PSBT_IN_MUSIG2_PARTIAL_SIG => {
                    let key = PartialSignatureKey::deserialize(&mut Cursor::new(&key.key))?;
                    let value = PartialSignatureValue::deserialize(&mut Cursor::new(value))?;

                    partial_signature.insert(key, value);
                }
                _ => { }
            }
        }

        Ok(MusigPsbtInput {
            participants,
            public_nonce,
            partial_signature,
        })
    }

    pub fn iter_musig_kvs<'a>(&'a self) -> impl Iterator<Item = MusigPsbtKeyValue<'a>> {
        self.participants.iter()
            .map(|(k, v)| MusigPsbtKeyValue::Participants((k, v)))
            .chain(
                self.public_nonce.iter()
                    .map(|(k, v)| MusigPsbtKeyValue::PublicNonce((k, v)))
            )
            .chain(
                self.partial_signature.iter()
                    .map(|(k, v)| MusigPsbtKeyValue::PartialSignature((k, v)))
            )
    }

    pub fn update(&mut self, kv: MusigPsbtKeyValue<'_>) {
        match kv {
            MusigPsbtKeyValue::Participants((k, v)) => { self.participants.insert(*k, v.clone()); }
            MusigPsbtKeyValue::PublicNonce((k, v)) => { self.public_nonce.insert(*k, *v); }
            MusigPsbtKeyValue::PartialSignature((k, v)) => { self.partial_signature.insert(*k, *v); }
        }
    }

    pub fn serialize_into_input(&self, input: &mut PsbtInput) -> Result<(), SerializeError> {
        for (agg_pk, participants) in self.participants.iter() {
            input.add_participants(*agg_pk, &participants[..])?;
        }

        for ((pk, agg_pk, tap_leaf), nonce) in self.public_nonce.iter() {
            input.add_nonce(*pk, *agg_pk, *tap_leaf, *nonce)?;
        }

        for ((pk, agg_pk, tap_leaf), sig) in self.partial_signature.iter() {
            input.add_partial_signature(*pk, *agg_pk, *tap_leaf, *sig)?;
        }

        Ok(())
    }
}

pub enum MusigPsbtKeyValue<'a> {
    Participants((&'a ParticipantPubkeysKey, &'a Vec<PublicKey>)),
    PublicNonce((&'a PublicNonceKey, &'a PublicNonceValue)),
    PartialSignature((&'a PartialSignatureKey, &'a PartialSignatureValue)),
}

impl<'a> MusigPsbtKeyValue<'a> {
    pub fn get_agg_pk(&self) -> &'a PublicKey {
        match self {
            MusigPsbtKeyValue::Participants(participants) => &participants.0,
            MusigPsbtKeyValue::PublicNonce(pubnonce) => &pubnonce.0.1,
            MusigPsbtKeyValue::PartialSignature(sig) => &sig.0.1,
        }
    }
}

