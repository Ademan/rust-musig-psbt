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
    BTreeMap,
    BTreeSet,
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

const MUSIG_PARTIAL_SIGNATURE_SERIALIZED_LEN: usize = 32;

pub const PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS: u8 = 0x19;
pub const PSBT_IN_MUSIG2_PUB_NONCE: u8 = 0x1a;
pub const PSBT_IN_MUSIG_PARTIAL_SIG: u8 = 0x1b;

// FIXME: psbt key types are actually var ints, once rust-bitcoin updates, update here
pub type PsbtKeyType = u8;

pub type ParticipantPubkeysKey = XOnlyPublicKey;
pub type ParticipantPubkeysValue = VariableLengthArray<PublicKey>;
pub type ParticipantPubkeysKeyValue = (ParticipantPubkeysKey, ParticipantPubkeysValue);

type SigningDataKey = (PublicKey, XOnlyPublicKey, Option<TapLeafHash>);

pub type PublicNonceKey = SigningDataKey;
pub type PublicNonceValue = MusigPubNonce;
pub type PublicNonceKeyValue = (PublicNonceKey, PublicNonceValue);

pub type PartialSignatureKey = SigningDataKey;
pub type PartialSignatureValue = MusigPartialSignature;
pub type PartialSignatureKeyValue = (PartialSignatureKey, PartialSignatureValue);

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

struct VariableLengthArray<T>(pub Vec<T>);

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
    const KEY_TYPE: PsbtKeyType = PSBT_IN_MUSIG_PARTIAL_SIG;
}

struct Derivation {
    pub master_fingerprint: [u8; 4],
    pub path: Vec<u32>,
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

pub fn deserialize_key<'a, K, V>() -> impl FnMut((&PsbtKey, &'a V)) -> (Result<K, DeserializeError>, &'a V)
where
    K: PsbtValue,
{
    |(key, value)| (K::deserialize(&mut Cursor::new(&key.key)), value)
}

// FIXME: gross
pub fn deserialize_key_second<K, V>() -> impl FnMut((&PsbtKey, V)) -> (Result<K, DeserializeError>, V)
where
    K: PsbtValue,
{
    |(key, value)| (K::deserialize(&mut Cursor::new(&key.key)), value)
}

pub fn deserialize_value<'a, K, V>() -> impl FnMut((K, &'a Vec<u8>)) -> (K, Result<V, DeserializeError>)
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

#[derive(Debug)]
pub enum AddItemError {
    SerializeError,
    DuplicateKeyError,
}

/// Extra functionality for psbt input proprietary key/value pairs
pub trait PsbtInputHelper {
    // Make return collection generic? maybe just for fun/edification... later
    fn get_participating_by_pk<F>(&self, f: F) -> Result<Vec<(ParticipantPubkeysKey, ParticipantPubkeysValue)>, DeserializeError>
    where
        F: FnMut(&Vec<PublicKey>) -> bool;

    fn get_participating_by_agg_pk<F>(&self, f: F) -> Result<Vec<(ParticipantPubkeysKey, ParticipantPubkeysValue)>, DeserializeError>
    where
        F: FnMut(&XOnlyPublicKey) -> bool;

    fn get_public_nonces<F>(&self, f: F) -> Result<Vec<(PublicKey, XOnlyPublicKey, Option<TapLeafHash>, MusigPubNonce)>, DeserializeError>
    where
        F: FnMut(&PublicKey, &XOnlyPublicKey, Option<&TapLeafHash>) -> bool;

    fn get_public_nonces_for(&self, agg_pks: &BTreeSet<(XOnlyPublicKey, Option<TapLeafHash>)>) -> Result<BTreeMap<(XOnlyPublicKey, Option<TapLeafHash>), BTreeMap<PublicKey, MusigPubNonce>>, DeserializeError>
    {
        let matching = self.get_public_nonces(|_pk, agg_pk, tap_leaf_hash|
            agg_pks.contains(&(agg_pk.to_owned(), tap_leaf_hash.map(|&x| x)))
        )?;

        let mut result: BTreeMap<(XOnlyPublicKey, Option<TapLeafHash>), BTreeMap<PublicKey, MusigPubNonce>> = BTreeMap::new();

        for (pk, agg_pk, tap_leaf_hash, pubnonce) in matching.into_iter() {
            if let Some(nonces) = result.get_mut(&(agg_pk, tap_leaf_hash)) {
                nonces.insert(pk, pubnonce);
            } else {
                let mut nonces = BTreeMap::new();
                nonces.insert(pk, pubnonce);

                result.insert((agg_pk, tap_leaf_hash), nonces);
            }
        }

        Ok(result)
    }

    fn get_partial_signatures<F>(&self, f: F) -> Result<Vec<(PublicKey, XOnlyPublicKey, Option<TapLeafHash>, MusigPartialSignature)>, DeserializeError>
    where
        F: FnMut(&PublicKey, &XOnlyPublicKey, Option<&TapLeafHash>) -> bool;

    fn get_partial_signatures_for(&self, agg_pks: &BTreeSet<(XOnlyPublicKey, Option<TapLeafHash>)>) -> Result<BTreeMap<(XOnlyPublicKey, Option<TapLeafHash>), BTreeMap<PublicKey, MusigPartialSignature>>, DeserializeError>
    {
        let matching = self.get_partial_signatures(|_pk, agg_pk, tap_leaf_hash|
            agg_pks.contains(&(agg_pk.to_owned(), tap_leaf_hash.map(|&x| x)))
        )?;

        let mut result: BTreeMap<(XOnlyPublicKey, Option<TapLeafHash>), BTreeMap<PublicKey, MusigPartialSignature>> = BTreeMap::new();

        for (pk, agg_pk, tap_leaf_hash, partial_sig) in matching.into_iter() {
            if let Some(nonces) = result.get_mut(&(agg_pk, tap_leaf_hash)) {
                nonces.insert(pk, partial_sig);
            } else {
                let mut nonces = BTreeMap::new();
                nonces.insert(pk, partial_sig);

                result.insert((agg_pk, tap_leaf_hash), nonces);
            }
        }

        Ok(result)
    }

    /// Serialize and add a key/value pair
    fn add_item<K: PsbtValue, V: PsbtValue> (&mut self, key: K, value: V) -> Result<(), AddItemError>
        where (K, V): PsbtKeyValue;

    fn add_participants(&mut self, agg_pk: XOnlyPublicKey, pubkeys: &[PublicKey]) -> Result<(), AddItemError> {
        self.add_item(agg_pk, VariableLengthArray(pubkeys.to_vec()))
    }

    fn add_nonce(&mut self, pubkey: PublicKey, agg_pk: XOnlyPublicKey, tap_leaf: Option<TapLeafHash>, nonce: MusigPubNonce) -> Result<(), AddItemError> {
        self.add_item((pubkey, agg_pk, tap_leaf), nonce)
    }

    fn add_partial_signature(&mut self, pubkey: PublicKey, agg_pk: XOnlyPublicKey, tap_leaf: Option<TapLeafHash>, sig: MusigPartialSignature) -> Result<(), AddItemError> {
        self.add_item((pubkey, agg_pk, tap_leaf), sig)
    }
}

/// Extra functionality for psbt input proprietary key/value pairs
impl PsbtInputHelper for PsbtInput {
    fn get_participating_by_pk<F>(&self, mut f: F) -> Result<Vec<(ParticipantPubkeysKey, ParticipantPubkeysValue)>, DeserializeError>
    where
        F: FnMut(&Vec<PublicKey>) -> bool,
    {
        self.unknown.iter()
            .filter(filter_key_type(PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS))
            .map(deserialize_value())
            .filter(|(ref key, ref value_result)|
                match value_result {
                    Err(_e) => { false },
                    Ok(VariableLengthArray(ref pks)) => { f(pks) }
                }
            )
            .map(deserialize_key_second())
            .map(map_kv_results())
            .collect::<Result<Vec<_>, _>>()
    }

    fn get_participating_by_agg_pk<F>(&self, mut f: F) -> Result<Vec<(ParticipantPubkeysKey, ParticipantPubkeysValue)>, DeserializeError>
    where
        F: FnMut(&XOnlyPublicKey) -> bool,
    {
        self.unknown.iter()
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

    fn get_public_nonces<F>(&self, mut f: F) -> Result<Vec<(PublicKey, XOnlyPublicKey, Option<TapLeafHash>, MusigPubNonce)>, DeserializeError>
    where
        F: FnMut(&PublicKey, &XOnlyPublicKey, Option<&TapLeafHash>) -> bool,
    {
        self.unknown.iter()
            .filter(filter_key_type(PSBT_IN_MUSIG2_PUB_NONCE))
            .map(deserialize_key::<PublicNonceKey, _>())
            .filter(|(ref key_result, ref _value)|
                match key_result {
                    Err(_e) => { false },
                    Ok((ref pubkey, ref found_agg_pk, ref tap_leaf_hash)) => {
                        f(pubkey, found_agg_pk, tap_leaf_hash.as_ref())
                    }
                }
            )
            .map(deserialize_value())
            .map(map_kv_results())
            .map(|i|
                i.map(|((pk, agg_pk, tap_leaf_hash), pub_nonce)|
                    (pk, agg_pk, tap_leaf_hash, pub_nonce)
                )
             )
            .collect::<Result<Vec<_>, _>>()
    }

    fn get_partial_signatures<F>(&self, mut f: F) -> Result<Vec<(PublicKey, XOnlyPublicKey, Option<TapLeafHash>, MusigPartialSignature)>, DeserializeError>
    where
        F: FnMut(&PublicKey, &XOnlyPublicKey, Option<&TapLeafHash>) -> bool,
    {
        self.unknown.iter()
            .filter(filter_key_type(PSBT_IN_MUSIG_PARTIAL_SIG))
            .map(deserialize_key::<PartialSignatureKey, _>())
            .filter(|(ref key_result, ref _value)|
                match key_result {
                    Err(_e) => { false },
                    Ok((ref pubkey, ref found_agg_pk, ref tap_leaf_hash)) => {
                        f(pubkey, found_agg_pk, tap_leaf_hash.as_ref())
                    }
                }
            )
            .map(deserialize_value())
            .map(map_kv_results())
            .map(|i|
                i.map(|((pk, agg_pk, tap_leaf_hash), partial_sig)|
                    (pk, agg_pk, tap_leaf_hash, partial_sig)
                )
             )
            .collect::<Result<Vec<_>, _>>()
    }

    fn add_item<K: PsbtValue, V: PsbtValue>(&mut self, key: K, value: V) -> Result<(), AddItemError>
        where (K, V): PsbtKeyValue
    {
        let (ser_key, ser_value) = (key, value).to_psbt()
            .map_err(|_| AddItemError::SerializeError)?;

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
