use bitcoin::{
    VarInt,
};

use bitcoin::consensus::encode::{
    Decodable,
    Encodable,
};

use bitcoin::psbt::{
    Input as PsbtInput,
    raw::Key as PsbtKey,
    //raw::ProprietaryKey,
    //raw::ProprietaryType,
};

use bitcoin::secp256k1::{
    constants::PUBLIC_KEY_SIZE,
    constants::SCHNORR_PUBLIC_KEY_SIZE,
};

use bitcoin::util::bip32::{
    ChildNumber,
    KeySource,
};

use bitcoin::util::taproot::{
    TapLeafHash,
};

use crate::{
    PublicKey,
    MusigPubNonce,
    MUSIG_PUBNONCE_SERIALIZED_LEN,
    MusigPartialSignature,
    XOnlyPublicKey,
};

use std::collections::{
    btree_map::Iter as BTreeIter,
};

use std::io::{
    Cursor,
    Error as IoError,
    ErrorKind as IoErrorKind,
    Read,
    Write,
};

use std::mem::{
    size_of,
};

use crate::{
    psbt::ParticipantIndex,
};

// FIXME: psbt key types are actually var ints, once rust-bitcoin updates, update here
pub type PsbtKeyType = u8;

const MUSIG_PARTIAL_SIGNATURE_SERIALIZED_LEN: usize = 32;

pub const PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS: u8 = 0x19;
pub const PSBT_IN_MUSIG2_PUB_NONCE: u8 = 0x1a;
pub const PSBT_IN_MUSIG_PARTIAL_SIG: u8 = 0x1b;

#[derive(Debug)]
pub enum SerializeError {
    IoError(IoError),
    SerializeError,
    SerializeElementError(usize),
}

#[derive(Debug)]
pub enum DeserializeError {
    IoError(IoError),
    DeserializeError,
    DeserializeElementError(usize),
}

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

pub struct VariableLengthArray<T>(pub Vec<T>);

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

impl PsbtValue for XOnlyPublicKey {
    fn serialize<W: Write>(&self, writer: &mut W) -> Result<(), SerializeError> {
        let pubkey_bytes = self.serialize();

        writer.write_all(&pubkey_bytes)
            .map_err(|e| SerializeError::IoError(e))?;

        Ok(())
    }

    fn deserialize<R: Read>(reader: &mut R) -> Result<Self, DeserializeError> {
        let mut pubkey_bytes = [0u8; SCHNORR_PUBLIC_KEY_SIZE];
        reader.read_exact(&mut pubkey_bytes)
            .map_err(|e| DeserializeError::IoError(e))?;

        let pubkey = XOnlyPublicKey::from_slice(&pubkey_bytes)
            .map_err(|_| DeserializeError::DeserializeError)?;

        Ok(pubkey)
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

        Ok((fingerprint[..].into(), path.into()))
    }
}

pub type ParticipantPubkeysKey = XOnlyPublicKey;
pub type ParticipantPubkeysValue = VariableLengthArray<PublicKey>;

type SigningDataKey = (PublicKey, XOnlyPublicKey, Option<TapLeafHash>);

pub type PublicNonceKey = SigningDataKey;
pub type PublicNonceValue = MusigPubNonce;

pub type PartialSignatureKey = SigningDataKey;
pub type PartialSignatureValue = MusigPartialSignature;

struct Derivation {
    pub master_fingerprint: [u8; 4],
    pub path: Vec<u32>,
}

struct MusigPublicNonceKeypair {
    pub index: ParticipantIndex,
    pub pubnonce: MusigPubNonce,
}

struct MusigPartialSignatureKeypair {
    pub pubkey: PublicKey,
    pub pubnonce: MusigPartialSignature,
}

#[repr(u8)]
pub enum MusigProprietaryKeySubtype {
    KeyspendParticipant = PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS,
    KeyspendPublicNonce = PSBT_IN_MUSIG2_PUB_NONCE,
    KeyspendPartialSignature = PSBT_IN_MUSIG_PARTIAL_SIG,
}

impl TryFrom<u8> for MusigProprietaryKeySubtype {
    type Error = ();

    fn try_from(x: u8) -> Result<Self, Self::Error> {
        if x == Self::KeyspendParticipant as u8 {
            return Ok(Self::KeyspendParticipant);
        } else if x == Self::KeyspendPublicNonce as u8 {
            return Ok(Self::KeyspendPublicNonce);
        } else if x == Self::KeyspendPartialSignature as u8 {
            return Ok(Self::KeyspendPartialSignature);
        } else {
            return Err(());
        }
    }
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

pub trait ToPsbtKeyValue: Sized {
    fn to_psbt(&self) -> Result<(PsbtKey, Vec<u8>), SerializeError>;
}

pub trait FromPsbtKeyValue: Sized {
    fn from_psbt(key: &PsbtKey, value: &Vec<u8>) -> Result<Self, DeserializeError>;
}

pub trait PsbtKeyValue {
    const KEY_TYPE: MusigProprietaryKeySubtype;
}

impl PsbtKeyValue for (ParticipantIndex, PublicKey) {
    const KEY_TYPE: MusigProprietaryKeySubtype = MusigProprietaryKeySubtype::KeyspendParticipant;
}

impl PsbtKeyValue for (PublicKey, MusigPubNonce) {
    const KEY_TYPE: MusigProprietaryKeySubtype = MusigProprietaryKeySubtype::KeyspendPublicNonce;
}

impl PsbtKeyValue for (PublicKey, MusigPartialSignature) {
    const KEY_TYPE: MusigProprietaryKeySubtype = MusigProprietaryKeySubtype::KeyspendPartialSignature;
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

impl<K: PsbtValue, V: PsbtValue> FromPsbtKeyValue for (K, V)
    where (K, V): PsbtKeyValue
{
    fn from_psbt(key: &PsbtKey, value: &Vec<u8>) -> Result<Self, DeserializeError> {
        if key.type_value != Self::KEY_TYPE as u8 {
            return Err(DeserializeError::DeserializeError);
        }

        let k = PsbtValue::deserialize(&mut Cursor::new(&key.key))
            .map_err(|_e| DeserializeError::DeserializeError)?;

        let v = PsbtValue::deserialize(&mut Cursor::new(value))
            .map_err(|_e| DeserializeError::DeserializeError)?;

        Ok((k, v))
    }
}

pub fn filter_key_type<'a>(key_type: PsbtKeyType) -> impl FnMut(&(&PsbtKey, &Vec<u8>)) -> bool {
    move |&(key, _value)| { key.type_value == key_type }
}

pub fn deserialize_key<'a, K, V>() -> impl FnMut((&'a PsbtKey, &'a V)) -> (Result<K, DeserializeError>, &'a V)
where
    K: PsbtValue,
{
    //|item: (&K, &'a V)| -> (Result<K, DeserializeError>, &'a V) {
    |(key, value)| (K::deserialize(&mut Cursor::new(&key.key)), value)
}

pub fn deserialize_value<'a, K, V>() -> impl FnMut((&'a K, &'a Vec<u8>)) -> (&'a K, Result<V, DeserializeError>)
where
    V: PsbtValue,
{
    |(key, value)| (key, V::deserialize(&mut Cursor::new(&value[..])))
}

pub fn map_kv_results<K, V, E>() -> impl FnMut((Result<K, E>, Result<V, E>)) -> Result<(K, V), E> {
    |tup| match tup {
        (Ok(k), Ok(v)) => { Ok((k, v)) },
        (Err(e), _) => { Err(e) },
        (_, Err(e)) => { Err(e) },
    }
}

/*
pub fn filter_agg_pk<'a>(agg_pk: &'a XOnlyPublicKey) -> impl FnMut(
{
}
*/

pub fn filter_deserialize_key<'a, I, K>(iter: I, key_type: PsbtKeyType)
    -> impl Iterator<Item=Result<(K, &'a Vec<u8>), DeserializeError>>
where
    I: Iterator<Item=&'a (PsbtKey, Vec<u8>)>,
    K: PsbtValue,
{
    iter.filter_map(move |(ref key, ref value)| {
        if key.type_value != key_type {
            return None;
        }

        match K::deserialize(&mut Cursor::new(&key.key)) {
            Ok(k) => { Some(Ok((k, value))) },
            Err(e) => { Some(Err(e)) },
        }
    })
}

pub fn get_participating_by_agg_pk<F>(input: &PsbtInput, f: F) -> Result<Vec<(ParticipantPubkeysKey, ParticipantPubkeysValue)>, DeserializeError>
where
    F: FnMut(&XOnlyPublicKey) -> bool,
{
    input.unknown.iter()
        .filter(filter_key_type(PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS))
        .map(deserialize_key())
        .filter(|(ref key_result, ref _value)|
            match key_result {
                Err(_e) => { false },
                Ok(ref found_agg_pk) => { f(found_agg_pk) }
            }
        )
        .map(deserialize_value())
        .map(map_kv_results())
        .collect::<Result<Vec<_>, _>>()
}

pub fn get_participating_by_pk<F>(input: &PsbtInput, f: F) -> Result<Vec<(ParticipantPubkeysKey, ParticipantPubkeysValue)>, DeserializeError>
where
    F: FnMut(&Vec<PublicKey>) -> bool,
{
    input.unknown.iter()
        .filter(filter_key_type(PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS))
        .map(deserialize_value())
        .filter(|(ref key, ref value_result)|
            match value_result {
                Err(_e) => { false },
                Ok(VariableLengthArray(ref pks)) => { f(pks) }
            }
        )
        .map(deserialize_key())
        .map(map_kv_results())
        .collect::<Result<Vec<_>, _>>()
}

pub fn deserialize<'a, I, K, V>(iter: I)
    -> impl Iterator<Item=Result<(K, V), DeserializeError>> + 'a
where
    I: Iterator<Item=Result<(K, &'a Vec<u8>), DeserializeError>> + 'a,
    V: PsbtValue,
{
    iter.map(|item| {
        let (key, ref value_bytes) = item?;

        match V::deserialize(&mut Cursor::new(value_bytes)) {
            Ok(value) => { Ok((key, value)) },
            Err(e) => { Err(e) },
        }
    })
}
