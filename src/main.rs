//! Headless IDA Pro CLI Tool
//!
//! All commands route through a persistent daemon process that holds
//! loaded binaries in memory via Unix socket IPC.

use clap::Parser;
use ida_mcp::cli::Cli;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

fn main() -> anyhow::Result<()> {
    // Suppress IDA library's "Thank you for using IDA" exit message.
    // The CLI client links idalib but only the daemon actually uses it;
    // however the dynamic library constructor registers an atexit handler.
    let _ = idalib::enable_console_messages(false);

    // Initialize logging to stderr (stdout is reserved for JSON output)
    tracing_subscriber::registry()
        .with(fmt::layer().with_writer(std::io::stderr))
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("ida_mcp=info")))
        .init();

    let cli = Cli::parse();
    ida_mcp::cli::run_cli(cli)
}
