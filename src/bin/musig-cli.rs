use base64::{
    engine::general_purpose::STANDARD,
    read::DecoderReader as Base64Reader,
    write::EncoderWriter as Base64Writer,
};

use bitcoin::consensus::encode::{
    Decodable,
    Encodable,
};

use bitcoin::network::constants::{
    Network,
};

use bitcoin::secp256k1::{
    Error as BitcoinError,
    Secp256k1,
};

use bitcoin::util::taproot::{
    TapBranchHash,
    TapLeafHash,
};

use clap::{
    Args,
    Parser,
    Subcommand,
};

use musig_psbt::{
    CoreContext,
    ExtraRand,
    MusigSessionId,
    PartiallySignedTransaction,
    ParticipantsAddResult,
    PsbtHelper,
    PsbtUpdater,
    PublicKey,
    SecretKey,
    SpendInfoAddResult,
    ZkpParity,
    ZkpSecp256k1,
};

use std::io;
use std::fs::{
    OpenOptions,
    read_to_string,
};

use std::path::{
    PathBuf,
};

use std::str::{
    FromStr,
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
    fn run(&self, _network: Network) {
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

        let mut in_psbt_file = OpenOptions::new()
            .read(true)
            .open(in_path)
            .expect("success opening psbt file");

        let mut psbt = PartiallySignedTransaction::consensus_decode_from_finite_reader(&mut in_psbt_file)
            .expect("success decoding psbt");

        let core_context = CoreContext::new(&zkp_secp, self.keys.to_owned(), None, None).expect("core context creation success");

        let add_spend_info_results = psbt.add_spend_info(&secp, &core_context)
            .expect("spend info add success");

        for (input_index, result) in add_spend_info_results.iter() {
            if let SpendInfoAddResult::Success {internal_key_modified: ikm, merkle_root_modified: mrm} = result {
                if *ikm {
                    println!("Modified taproot internal key for input {input_index}");
                }

                if *mrm {
                    println!("Modified taproot merkle root for input {input_index}");
                }
            }
        }

        let add_participants_results = psbt.add_participants(&secp, &core_context)
            .expect("participants add success");

        for (input_index, result) in add_participants_results.into_iter() {
            if ParticipantsAddResult::ParticipantsAdded == result {
                println!("Added parcitipants to input {input_index}");
            }
        }

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

        let tap_leaf: Option<TapLeafHash> = None;
        let merkle_root: Option<TapBranchHash> = None;

        let core_context = CoreContext::new(&zkp_secp, self.keys.to_owned(), merkle_root, tap_leaf).expect("core context creation success");

        let pubkey = if self.untweaked {
            core_context.inner_agg_pk
        } else {
            core_context.agg_pk
        };

        let compressed_pk = pubkey.public_key(ZkpParity::Even);

        let address = core_context.address(&secp, network);

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

        //let keyspend_context = KeyspendContext::from_participant_pubkeys(&zkp_secp, prefix, pubkey, self.keys.to_owned(), None).expect("success");

        println!("Step 1. Base64 Encoded PSBT (initial): ");

        let mut aggregate_psbt = read_psbt();

        let participating = aggregate_psbt.get_participating_for_pk(&zkp_secp, &pubkey)
            .expect("success getting participating");

        let nonce_generate_contexts: Vec<_> = participating.iter()
            .map(|(index, ctx)| {
                println!("Signing index {index}");
                let session = MusigSessionId::random();

                let extra = ExtraRand::tagged(b"musig/extra-rand").nanotime();
                let sign_context = ctx.add_nonce(&zkp_secp, pubkey, &mut aggregate_psbt, *index, session, extra.into_bytes())
                    .expect("add nonce");

                (index, sign_context)
            })
            .collect();

        println!("With nonce: ");
        write_psbt(&aggregate_psbt);
        println!();

        println!("Step 2. Base64 Encoded PSBT with all nonces (Step 1 complete for all participants):");
        let mut psbt_with_nonces = read_psbt();

        let aggregate_contexts: Vec<_> = nonce_generate_contexts.into_iter()
            .map(|(index, ctx)| {
                let sigaggctx = ctx.sign(&zkp_secp, &privkey, &mut psbt_with_nonces, *index)
                    .expect("sign");

                (index, sigaggctx)
            })
            .collect();

        println!("With (partial) signature: ");
        write_psbt(&psbt_with_nonces);
        println!();

        println!("Step 3. Base64 Encoded PSBT with all partial signatures (Step 2 complete for all participants):");
        let mut psbt_with_partial_signatures = read_psbt();

        aggregate_contexts.into_iter()
            .for_each(|(index, ctx)| {
                ctx.aggregate_signatures(&zkp_secp, &mut psbt_with_partial_signatures, *index)
                    .expect("aggregate signatures");
            });

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
