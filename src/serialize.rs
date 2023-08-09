use bitcoin::{
    VarInt,
};

use bitcoin::consensus::encode::{
    Decodable,
    Encodable,
};

use bitcoin::psbt::{
    raw::ProprietaryKey,
    raw::ProprietaryType,
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

use std::marker::{
    PhantomData,
};

use std::mem::{
    size_of,
};

use crate::{
    psbt::ParticipantIndex,
};

const MUSIG_PARTIAL_SIGNATURE_SERIALIZED_LEN: usize = 32;

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

struct ParticipantKey {
    pub index: ParticipantIndex,
    pub pubkey: PublicKey,
}

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
    KeyspendParticipant = 0,
    KeyspendPublicNonce = 1,
    KeyspendPartialSignature = 2,
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
    fn to_psbt<'a>(&self, prefix: &'a Vec<u8>) -> Result<(ProprietaryKey, Vec<u8>), SerializeError>;
}

pub trait FromPsbtKeyValue: Sized {
    fn from_psbt(key: &ProprietaryKey, value: &Vec<u8>) -> Result<Self, DeserializeError>;
}

pub trait ProprietaryKeyConvertible {
    const SUBTYPE: MusigProprietaryKeySubtype;
}

impl ProprietaryKeyConvertible for (ParticipantIndex, PublicKey) {
    const SUBTYPE: MusigProprietaryKeySubtype = MusigProprietaryKeySubtype::KeyspendParticipant;
}

impl ProprietaryKeyConvertible for (PublicKey, MusigPubNonce) {
    const SUBTYPE: MusigProprietaryKeySubtype = MusigProprietaryKeySubtype::KeyspendPublicNonce;
}

impl ProprietaryKeyConvertible for (PublicKey, MusigPartialSignature) {
    const SUBTYPE: MusigProprietaryKeySubtype = MusigProprietaryKeySubtype::KeyspendPartialSignature;
}

impl<K: PsbtValue, V: PsbtValue> ToPsbtKeyValue for (K, V)
    where (K, V): ProprietaryKeyConvertible
{
    fn to_psbt<'a>(&self, prefix: &'a Vec<u8>) -> Result<(ProprietaryKey, Vec<u8>), SerializeError> {
        let mut key_buf = Vec::<u8>::new();
        self.0.serialize(&mut key_buf)?;

        let mut value_buf = Vec::<u8>::new();
        PsbtValue::serialize(&self.1, &mut value_buf)?;

        Ok((ProprietaryKey {
            prefix: prefix.to_owned(),
            subtype: Self::SUBTYPE as u8,
            key: key_buf,
        }, value_buf))
    }
}

impl<K: PsbtValue, V: PsbtValue> FromPsbtKeyValue for (K, V)
    where (K, V): ProprietaryKeyConvertible
{
    fn from_psbt(key: &ProprietaryKey, value: &Vec<u8>) -> Result<Self, DeserializeError> {
        if key.subtype != Self::SUBTYPE as u8 {
            return Err(DeserializeError::DeserializeError);
        }

        let k = PsbtValue::deserialize(&mut Cursor::new(&key.key))
            .map_err(|_e| DeserializeError::DeserializeError)?;

        let v = PsbtValue::deserialize(&mut Cursor::new(value))
            .map_err(|_e| DeserializeError::DeserializeError)?;

        Ok((k, v))
    }
}

pub struct ProprietaryKeyIterator<'a, K: PsbtValue, V: PsbtValue> {
    keys: BTreeIter<'a, ProprietaryKey, Vec<u8>>,
    done: bool,
    prefix: &'a [u8],
    subtype: ProprietaryType,
    _type: PhantomData<(K, V)>,
}

impl<'a, K: PsbtValue, V: PsbtValue> ProprietaryKeyIterator<'a, K, V> {
    pub fn new(keys: BTreeIter<'a, ProprietaryKey, Vec<u8>>, prefix: &'a [u8], subtype: ProprietaryType) -> Self {
        ProprietaryKeyIterator {
            keys,
            done: false,
            prefix, subtype,
            _type: PhantomData,
        }
    }
}

impl<'a, K: PsbtValue, V: PsbtValue> Iterator for ProprietaryKeyIterator<'a, K, V>
    where (K, V): ProprietaryKeyConvertible
{
    type Item = Result<(K, V), DeserializeError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }

        loop {
            match self.keys.next() {
                Some((key, value)) => {
                    if key.prefix == self.prefix &&
                       key.subtype == self.subtype {
                        let result_key = match K::deserialize(&mut Cursor::new(&key.key)) {
                            Ok(k) => k,
                            Err(e) => { return Some(Err(e)) },
                        };

                        let result_value = match V::deserialize(&mut Cursor::new(value)) {
                            Ok(k) => k,
                            Err(e) => { return Some(Err(e)) },
                        };

                        return Some(Ok((result_key, result_value)));
                    }
                },
                None => {
                    self.done = true;
                    return None;
                },
            }
        }
    }
}
