use std::path::PathBuf;

use clap::Args;
use rauha_evidence::receipt::SignedExecutionReceipt;

use super::output::{self, OutputMode};

#[derive(Args)]
pub struct ReceiptArgs {
    /// Receipt JSON or `rauha sandbox --json` output containing a receipt.
    pub file: PathBuf,
    /// Trusted daemon Ed25519 public-key file.
    #[arg(long)]
    pub public_key: PathBuf,
}

pub fn verify(args: ReceiptArgs, out: OutputMode) -> anyhow::Result<()> {
    let value: serde_json::Value = serde_json::from_slice(&std::fs::read(&args.file)?)?;
    let receipt: SignedExecutionReceipt =
        serde_json::from_value(value.get("receipt").cloned().unwrap_or(value))?;
    let trusted_public_key = std::fs::read_to_string(&args.public_key)?;
    receipt
        .verify_trusted(&trusted_public_key)
        .map_err(anyhow::Error::msg)?;
    let digest = receipt.sha256();
    let result = output::ReceiptVerification {
        ok: true,
        schema: receipt.payload.schema,
        task_id: receipt.payload.task_id,
        digest,
    };
    output::print(out, &result, || {
        println!("verified: {} {}", result.task_id, result.digest)
    });
    Ok(())
}
