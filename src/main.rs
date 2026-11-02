//! `akkoro` command-line interface.

use clap::{Parser, Subcommand};
use akkoro::config::{hex_encode, Config, IdentityFile};
use akkoro::crypto::IdentityKeys;

#[derive(Parser)]
#[command(name = "akkoro", version, about = "Post-quantum, low-latency L3 tunnel (lab-only)")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate a new long-term identity (X25519 + ML-KEM-768).
    Keygen {
        /// Output identity file path.
        #[arg(short, long, default_value = "identity.toml")]
        out: String,
    },
    /// Print this node's public keys and a ready-to-paste peer snippet.
    Pubkey {
        /// Identity file path.
        #[arg(short, long, default_value = "identity.toml")]
        identity: String,
    },
    /// Run the tunnel daemon.
    Run {
        /// Config file path.
        #[arg(short, long, default_value = "akkoro.toml")]
        config: String,
    },
}

fn main() {
    let cli = Cli::parse();
    let r = match cli.cmd {
        Cmd::Keygen { out } => cmd_keygen(&out),
        Cmd::Pubkey { identity } => cmd_pubkey(&identity),
        Cmd::Run { config } => akkoro::daemon::run(Config::load(&config).expect("config")).map_err(|e| e.into()),
    };
    if let Err(e) = r {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn cmd_keygen(out: &str) -> Result<(), Box<dyn std::error::Error>> {
    let id = IdentityKeys::generate();
    let idf = IdentityFile {
        dh_private: hex_encode(&id.dh_private.to_bytes()),
        kem_seed: hex_encode(&id.kem.seed_bytes()),
    };
    let text = toml::to_string_pretty(&idf)?;
    std::fs::write(out, text)?;
    println!("[+] identity written to {out}");
    println!("    dh_public = {}", hex_encode(&id.dh_public_bytes()));
    println!("    kem_ek    = {}...", &hex_encode(&id.kem.encap_bytes())[..32]);
    Ok(())
}

fn cmd_pubkey(identity: &str) -> Result<(), Box<dyn std::error::Error>> {
    let text = std::fs::read_to_string(identity)?;
    let idf: IdentityFile = toml::from_str(&text)?;
    let dh: [u8; 32] = akkoro::config::hex_decode(&idf.dh_private).ok_or("bad dh_private")?;
    let seed: [u8; 64] = akkoro::config::hex_decode(&idf.kem_seed).ok_or("bad kem_seed")?;
    let id = IdentityKeys::from_parts(dh, seed).ok_or("bad identity")?;
    println!("dh_public = {}", hex_encode(&id.dh_public_bytes()));
    println!("kem_ek    = {}", hex_encode(&id.kem.encap_bytes()));
    Ok(())
}
