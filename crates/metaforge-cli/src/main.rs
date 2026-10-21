mod args;
mod commands;
mod export;
mod table;

use args::{Cli, Commands, ScanArgs};
use clap::Parser;
use commands::{
    execute_audit, execute_batch, execute_comment, execute_convert, execute_dump, execute_probe,
    execute_sanitize, execute_scan,
};
use std::process::ExitCode;

fn main() -> ExitCode {
    let cli = Cli::parse();

    let result = match cli.command {
        Some(Commands::Scan(args)) => execute_scan(&args, cli.format),
        Some(Commands::Audit(args)) => execute_audit(&args, cli.format),
        Some(Commands::Sanitize(args)) => execute_sanitize(&args),
        Some(Commands::Comment(args)) => execute_comment(&args),
        Some(Commands::Dump(args)) => execute_dump(&args),
        Some(Commands::Convert(args)) => execute_convert(&args, cli.format),
        Some(Commands::Batch(args)) => execute_batch(&args, cli.format),
        Some(Commands::Probe(args)) => execute_probe(&args, cli.format),
        None => {
            if let Some(file) = cli.file {
                let scan_args = ScanArgs {
                    file,
                    exif_only: false,
                    gps_only: false,
                };
                execute_scan(&scan_args, cli.format)
            } else {
                eprintln!("Error: No input file or subcommand specified.");
                eprintln!("Run 'metaforge --help' for usage instructions.");
                return ExitCode::FAILURE;
            }
        }
    };

    match result {
        Ok(_) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("\n❌ Error: {}\n", err);
            ExitCode::FAILURE
        }
    }
}
