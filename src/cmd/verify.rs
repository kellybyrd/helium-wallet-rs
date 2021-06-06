use crate::{cmd::*, keypair::Keypair, mnemonic::SeedType, result::Result, wallet::Wallet};
use prettytable::{format, Table};
use serde_json::json;

/// Verify an encypted wallet
#[derive(Debug, StructOpt)]
pub struct Cmd {
    #[structopt(long, possible_values = &["bip39", "mobile"], case_insensitive = true)]
    /// Use a BIP39 or mobile app seed phrase to generate the wallet keys
    seed: Option<SeedType>,
}

impl Cmd {
    pub async fn run(&self, opts: Opts) -> Result {
        let password = get_password(false)?;
        let wallet = load_wallet(opts.files)?;
        let decryped_wallet = wallet.decrypt(password.as_bytes());
        print_result(&wallet, &decryped_wallet, self.seed.as_ref(), opts.format)
    }
}

pub fn print_result(
    wallet: &Wallet,
    decryped_wallet: &Result<Keypair>,
    seed_type: Option<&SeedType>,
    format: OutputFormat,
) -> Result {
    let address = wallet.address().unwrap_or_else(|_| "unknown".to_string());
    let phrase = decryped_wallet
        .as_ref()
        .unwrap()
        .phrase(seed_type)
        .join(" ");

    match format {
        OutputFormat::Table => {
            let mut table = Table::new();
            table.set_format(*format::consts::FORMAT_NO_LINESEP_WITH_TITLE);
            if seed_type.is_none() {
                table.set_titles(row!["Address", "Sharded", "Verify", "PwHash"]);
                table.add_row(row![
                    address,
                    wallet.is_sharded(),
                    decryped_wallet.is_ok(),
                    wallet.pwhash()
                ]);
            } else {
                table.set_titles(row!["Address", "Sharded", "Verify", "PwHash", "Phrase"]);
                table.add_row(row![
                    address,
                    wallet.is_sharded(),
                    decryped_wallet.is_ok(),
                    wallet.pwhash(),
                    phrase
                ]);
            }
            print_table(&table)
        }
        OutputFormat::Json => {
            let mut table = json!({
                "address": address,
                "sharded": wallet.is_sharded(),
                "verify": decryped_wallet.is_ok(),
                "pwhash": wallet.pwhash().to_string()
            });
            if seed_type.is_some() {
                table["phrase"] = serde_json::Value::String(phrase);
            }
            print_json(&table)
        }
    }
}
