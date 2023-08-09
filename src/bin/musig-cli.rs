use base64::{
    engine::general_purpose::STANDARD_NO_PAD,
    read::DecoderReader as Base64Reader,
    write::EncoderWriter as Base64Writer,
};

use bitcoin::{
    Address,
    OutPoint,
    Sequence,
    Script,
    Txid,
    TxIn,
    TxOut,
    Witness,
    blockdata::locktime::LockTime,
    Transaction,
};

use bitcoin::consensus::encode::{
    Decodable,
    deserialize,
    Encodable,
    serialize,
    serialize_hex
};

use bitcoin::hashes::{
    Hash,
};

use bitcoin::hashes::sha256d::{
    Hash as Sha256,
};

use bitcoin::network::constants::{
    Network,
};

use bitcoin::secp256k1::{
    Error as BitcoinError,
    Secp256k1,
    XOnlyPublicKey,
};

use bitcoin::util::taproot::{
    TapBranchHash,
    TapTweakHash,
};

use clap::{
    Args,
    Parser,
    Subcommand,
};

use musig_psbt::{
    FromZkp,
    KeyspendContext,
    MusigAggNonce,
    MusigKeyAggCache,
    MusigSessionId,
    SecretKey,
    PublicKey,
    ToZkp,
    ZkpAll,
    ZkpKeyPair,
    ZkpPublicKey,
    ZkpSecp256k1,
    ZkpSecretKey,
    ZkpSigning,
    ZkpVerification,
    PartiallySignedTransaction,
};

use std::io;
use std::fmt::LowerHex;
use std::fs::{
    read_to_string,
    File,
};

use std::path::{
    Path,
    PathBuf,
};

use std::str::{
    FromStr,
    Chars,
};

#[derive(Parser)]
#[command(name = "musig-cli")]
struct CommandLine {
    #[command(subcommand)]
    command: Command,

    #[arg(default_value="signet")]
    network: Network,
}

#[derive(Clone, Subcommand)]
enum Command {
    Aggregate(Aggregate),
    Sign(Sign),
}

#[derive(Clone, Args)]
struct Aggregate {
    #[arg(required=true, value_parser = parse_pubkey)]
    keys: Vec<PublicKey>,
}

#[derive(Clone, Args)]
struct Sign {
    #[arg(required=true)]
    privkey_path: PathBuf,
    #[arg(required=true, value_parser = parse_pubkey)]
    keys: Vec<PublicKey>,
}

fn parse_pubkey(s: &str) -> Result<PublicKey, BitcoinError> {
    PublicKey::from_str(s)
}

fn aggregate(network: Network, keys: &Vec<PublicKey>) {
    let secp = Secp256k1::new();
    let zkp_secp = ZkpSecp256k1::new();
    let zkp_keys: Vec<ZkpPublicKey> = keys.iter().map(|k| k.to_zkp()).collect();
    let keyagg_cache = MusigKeyAggCache::new(&zkp_secp, &zkp_keys[..]);

    let agg_pk = keyagg_cache.agg_pk();

    let address = Address::p2tr(&secp, agg_pk.from_zkp(), None, network);

    println!("{}", address);
}

struct HexStringReader<I>
{
    iter: I,
}

impl<'a> From<&'a str> for HexStringReader<Chars<'a>>
{
    fn from(s: &'a str) -> Self {
        HexStringReader { iter: s.chars() }
    }
}

enum ReadHexError {
    UnexpectedEndOfFile,
    InvalidCharacter(char),
}

impl<I> io::Read for HexStringReader<I>
where
    I: Iterator<Item=char>
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut i = 0;

        while i < buf.len() {
            let high_char = match self.iter.next() {
                Some(c) => { c },
                None => { break; },
            };

            let high = high_char
                .to_digit(16)
                .ok_or(io::Error::from(io::ErrorKind::InvalidData))?;

            let low_char = self.iter.next()
                .ok_or(io::Error::from(io::ErrorKind::UnexpectedEof))?;

            let low = low_char
                .to_digit(16)
                .ok_or(io::Error::from(io::ErrorKind::InvalidData))?;

            buf[i] = ((high << 8) | (low << 0)) as u8;

            i += 1;
        }

        Ok(i)
    }
}

fn read_psbt() -> PartiallySignedTransaction {
    let mut line_in = String::new();

    if line_in.ends_with("\n") {
        line_in.pop();

        if line_in.ends_with("\r") {
            line_in.pop();
        }
    }

    io::stdin().read_line(&mut line_in).expect("input");

    if !line_in.is_ascii() {
        panic!("expected ascii");
    }

    let line_bytes = line_in.as_bytes();

    let mut reader = Base64Reader::new(line_bytes, &STANDARD_NO_PAD);

    PartiallySignedTransaction::consensus_decode_from_finite_reader(&mut reader).expect("valid PSBT hex")
}

fn write_psbt(psbt: &PartiallySignedTransaction) {
    psbt.consensus_encode(&mut Base64Writer::new(&mut io::stdout(), &STANDARD_NO_PAD)).expect("successful writing");
}

fn sign(privkey_path: &Path, participant_pubkeys: &Vec<PublicKey>) {
    let secp = Secp256k1::new();
    let zkp_secp = ZkpSecp256k1::new();

    let privkey_file = read_to_string(privkey_path).expect("private key file exists");
    let privkey = SecretKey::from_str(&privkey_file.trim()).expect("file contents");

    let pubkey = privkey.public_key(&secp);

    let prefix = b"musig".to_vec();

    let keyspend_context = KeyspendContext::from_participant_pubkeys(&zkp_secp, prefix, pubkey, participant_pubkeys.to_owned(), None).expect("success");

    println!("Step 1. Base64 Encoded PSBT (initial): ");

    let mut aggregate_psbt = read_psbt();

    let index_count = aggregate_psbt.unsigned_tx.input.len();

    assert!(index_count > 0);

    println!("Signing for which index? 0 <= i < {}", index_count);

    let mut line_in = String::new();
    io::stdin().read_line(&mut line_in).expect("input");
    let input_index: usize = line_in.trim().parse().expect("valid input index");

    assert!(input_index < index_count);

    let session = MusigSessionId::random();

    // TODO: timestamp into extra_rand
    let signing_context = keyspend_context.add_nonce(&mut aggregate_psbt, input_index, session, [0u8; 32])
        .expect("nonce generate success");

    println!("With nonce: ");
    write_psbt(&aggregate_psbt);

    println!("Step 2. Base64 Encoded PSBT with all nonces (Step 1 complete for all participants):");
    let mut psbt_with_nonces = read_psbt();

    let sig_agg_context = signing_context.sign(&privkey.to_zkp(), &mut psbt_with_nonces, input_index).expect("signing success");
    println!("With (partial) signature: ");
    write_psbt(&aggregate_psbt);

    println!("Step 2. Base64 Encoded PSBT with all partial signatures (Step 2 complete for all participants):");
    let mut psbt_with_partial_signatures = read_psbt();

    sig_agg_context.aggregate_signatures(&mut psbt_with_partial_signatures, input_index).expect("signing success"); 

    println!("With signature: ");
    write_psbt(&aggregate_psbt);
}

fn main() {
    let args = CommandLine::parse();

    match args.command {
        Command::Aggregate(ref agg) => {
            aggregate(args.network, &agg.keys);
        },
        Command::Sign(ref sign_args) => {
            sign(&sign_args.privkey_path, &sign_args.keys);
        },
    }
}
