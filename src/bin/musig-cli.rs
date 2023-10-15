use base64::{
    engine::general_purpose::STANDARD,
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
    CoreContext,
    ExtraRand,
    FromZkp,
    KeyspendContext,
    MusigAggNonce,
    MusigKeyAggCache,
    MusigSessionId,
    PartiallySignedTransaction,
    PublicKey,
    SecretKey,
    SpendInfoAddResult,
    ToZkp,
    tweak_keyagg,
    ZkpAll,
    ZkpKeyPair,
    ZkpPublicKey,
    ZkpParity,
    ZkpSecp256k1,
    ZkpSecretKey,
    ZkpSigning,
    ZkpVerification,
};

use std::io;
use std::fmt::LowerHex;
use std::fs::{
    OpenOptions,
    read_to_string,
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
    Aggregate(AggregateSubcommand),
    Sign(SignSubcommand),
    Update(UpdateSubcommand),
}

#[derive(Clone, Args)]
struct AggregateSubcommand {
    #[arg(required=true, value_parser = parse_pubkey)]
    keys: Vec<PublicKey>,

    #[arg(short = 'p', long = "show-pubkey", default_value="false")]
    show_pubkey: bool,

    #[arg(short = 'a', long = "show-address", default_value="true")]
    show_address: bool,

    #[arg(short = 'u', long = "untweaked", default_value="false")]
    untweaked: bool,

    // XXX: compressed pubkey being smaller than the "pubkey" may confuse users unfamiliar with
    // x-only pubkeys. This tool isn't really intended for general use anyway.
    #[arg(short = 'c', long = "show-compressed-pubkey", default_value="false")]
    show_compressed_pubkey: bool,

    // TODO: allow tap leaf hash
}

#[derive(Clone, Args)]
struct UpdateSubcommand {
    #[arg(required=true, value_parser = parse_pubkey)]
    keys: Vec<PublicKey>,

    //Option<TapBranchHash>,

    #[arg(short = 'i', long = "in")]
    in_path: Option<PathBuf>,

    #[arg(short = 'o', long = "out")]
    out_path: Option<PathBuf>,

    #[arg(long = "in-place", default_value = "false")]
    in_place: bool,

    //add_participants: bool,
    // TODO: Control which things to update
    // TODO: Allow control over which inputs to inspect
}

impl UpdateSubcommand {
    fn run(&self, network: Network) {
        let prefix = b"musig".to_vec();

        // TODO: relax and handle stdin/stdout instead
        let in_path = self.in_path.clone().expect("in path");

        let out_path = if self.in_place {
            in_path.clone()
        } else {
            // TODO: relax and handle stdin/stdout instead
            assert!(self.out_path.is_some());
            self.out_path.clone().expect("out path")
        };

        let secp = Secp256k1::new();
        let zkp_secp = ZkpSecp256k1::new();

        let core_context = CoreContext::new(&zkp_secp, self.keys.to_owned()).expect("success");

        let updater = core_context.updater(&zkp_secp);

        let mut in_psbt_file = OpenOptions::new()
            .read(true)
            .open(in_path)
            .expect("success opening psbt file");

        let mut psbt = PartiallySignedTransaction::consensus_decode_from_finite_reader(&mut in_psbt_file)
            .expect("success decoding psbt");

        let mut modified = false;

        psbt.inputs.iter_mut()
            .enumerate()
            .for_each(|(i, input)|
                match updater.add_spend_info(&secp, input) {
                Ok(SpendInfoAddResult::Success{
                    internal_key_modified: ikm,
                    merkle_root_modified: mrm,
                }) => {
                    // FIXME: remove println
                    println!("modified {i} internal key: {ikm}");
                    println!("modified {i} merkle root: {mrm}");
                    modified = modified || ikm || mrm;
                },
                // FIXME: remove println
                Ok(SpendInfoAddResult::InputNoMatch) => { println!("no match {i}"); },
                Err(e) => {
                    // TODO
                    println!("E: Input {i} {e:?}");
                }
                }
            );

        let mut psbt_out_file = OpenOptions::new()
            .write(true)
            .create(true)
            .open(out_path)
            .expect("success opening output file");

        psbt.consensus_encode(&mut psbt_out_file)
            .expect("success writing");
    }
}

#[derive(Clone, Args)]
struct SignSubcommand {
    #[arg(required=true)]
    privkey_path: PathBuf,
    #[arg(required=true, value_parser = parse_pubkey)]
    keys: Vec<PublicKey>,
}

impl AggregateSubcommand {
    fn run(&self, network: Network) {
        let secp = Secp256k1::new();
        let zkp_secp = ZkpSecp256k1::new();
        let zkp_keys: Vec<ZkpPublicKey> = self.keys.iter().map(|k| k.to_zkp()).collect();
        let mut keyagg_cache = MusigKeyAggCache::new(&zkp_secp, &zkp_keys[..]);

        let tap_leaf: Option<TapBranchHash> = None;

        let (agg_pk, tweaked_agg_pk) = tweak_keyagg(&zkp_secp, &mut keyagg_cache, tap_leaf).expect("successful tweak");

        let pubkeys = [agg_pk, tweaked_agg_pk];
        let mut pubkey_selection = 1;

        let pubkey = if self.untweaked {
            agg_pk
        } else {
            tweaked_agg_pk
        };

        let compressed_pk = pubkey.public_key(ZkpParity::Even);

        let address = Address::p2tr(&secp, agg_pk.from_zkp(), tap_leaf, network);

        if self.show_pubkey && self.show_address && self.show_compressed_pubkey {
            println!("Aggregate Public Key: {}", compressed_pk);
            println!("Address: {}", address);
        } else if self.show_pubkey && self.show_address {
            println!("Aggregate Public Key: {}", pubkey);
            println!("Address: {}", address);
        } else if self.show_pubkey && self.show_compressed_pubkey {
            println!("{}", compressed_pk);
        } else if self.show_pubkey {
            println!("{}", pubkey);
        } else if self.show_address {
            println!("{}", address);
        }
    }
}

impl SignSubcommand {
    fn run(&self) {
        let secp = Secp256k1::new();
        let zkp_secp = ZkpSecp256k1::new();

        let privkey_file = read_to_string(&self.privkey_path).expect("private key file exists");
        let privkey = SecretKey::from_str(&privkey_file.trim()).expect("file contents");

        let pubkey = privkey.public_key(&secp);

        let prefix = b"musig".to_vec();

        let keyspend_context = KeyspendContext::from_participant_pubkeys(&zkp_secp, prefix, pubkey, self.keys.to_owned(), None).expect("success");

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

        let extra = ExtraRand::tagged(b"musig/extra-rand").nanotime();
        let signing_context = keyspend_context.add_nonce(&mut aggregate_psbt, input_index, session, extra.into_bytes())
            .expect("nonce generate success");

        println!("With nonce: ");
        write_psbt(&aggregate_psbt);
        println!();

        println!("Step 2. Base64 Encoded PSBT with all nonces (Step 1 complete for all participants):");
        let mut psbt_with_nonces = read_psbt();

        let sig_agg_context = signing_context.sign(&privkey.to_zkp(), &mut psbt_with_nonces, input_index).expect("signing success");
        println!("With (partial) signature: ");
        write_psbt(&psbt_with_nonces);
        println!();

        println!("Step 2. Base64 Encoded PSBT with all partial signatures (Step 2 complete for all participants):");
        let mut psbt_with_partial_signatures = read_psbt();

        sig_agg_context.aggregate_signatures(&mut psbt_with_partial_signatures, input_index).expect("signing success"); 

        println!("With signature: ");
        write_psbt(&psbt_with_partial_signatures);
        println!();
    }
}

fn parse_pubkey(s: &str) -> Result<PublicKey, BitcoinError> {
    PublicKey::from_str(s)
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

    let line_bytes = line_in.trim().as_bytes();

    let mut reader = Base64Reader::new(line_bytes, &STANDARD);

    PartiallySignedTransaction::consensus_decode_from_finite_reader(&mut reader).expect("valid PSBT base64")
}

fn write_psbt(psbt: &PartiallySignedTransaction) {
    psbt.consensus_encode(&mut Base64Writer::new(&mut io::stdout(), &STANDARD)).expect("successful writing");
}

fn main() {
    let args = CommandLine::parse();

    match args.command {
        Command::Aggregate(ref agg) => {
            agg.run(args.network)
        },
        Command::Sign(ref sign) => {
            sign.run()
        },
        Command::Update(ref update) => {
            update.run(args.network)
        },
    }
}
