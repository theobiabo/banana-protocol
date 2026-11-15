use banana_palm::{generate_keys, read_key, reconstruct_file, split_file};
use clap::{Parser, Subcommand};
use ring::signature::Ed25519KeyPair;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "banana-palm",
    about = "Create and restore encrypted .palm fragments"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate private keys and a public sender key in a new directory.
    Keygen { directory: PathBuf },
    /// Split a stable file into a new directory of signed, encrypted fragments.
    Split {
        source: PathBuf,
        directory: PathBuf,
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        signing_seed: PathBuf,
    },
    /// Restore a file, validating against a separately trusted sender public key.
    Restore {
        directory: PathBuf,
        destination: PathBuf,
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        sender: PathBuf,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    match Cli::parse().command {
        Command::Keygen { directory } => generate_keys(directory)?,
        Command::Split {
            source,
            directory,
            key,
            signing_seed,
        } => {
            let seed = read_key(signing_seed)?;
            let signer = Ed25519KeyPair::from_seed_unchecked(&seed)
                .map_err(|_| std::io::Error::other("invalid signing seed"))?;
            let count = split_file(source, directory, &read_key(key)?, &signer)?;
            println!("Created {count} .palm fragment(s)");
        }
        Command::Restore {
            directory,
            destination,
            key,
            sender,
        } => {
            reconstruct_file(directory, destination, &read_key(key)?, &read_key(sender)?)?;
            println!("Restored and verified the original file");
        }
    }
    Ok(())
}
