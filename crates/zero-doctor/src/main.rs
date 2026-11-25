//! `zero-doctor` binary (T-DOC-01, DOC-01, DOC-09).
//!
//! Runs the plugin-free core and prints the report. It never loads plugins and
//! never contacts the daemon, so it works while the daemon, kernel, and mesh
//! are dead. Every path exits zero for this task: a diagnosis that cannot run
//! is not a reason to fail a scripted probe.

use std::process::ExitCode;
use zero_doctor::{run_core, VERSION};

const HELP: &str = "usage: zero-doctor [--json] [--version]

Runs the independent doctor core. No plugins, no daemon socket.

options:
  --json      print the DoctorReport as JSON
  --version   print the doctor version and exit
  --help      print this help and exit
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!("zero-doctor {VERSION} (independent)");
        return ExitCode::SUCCESS;
    }
    if args.iter().any(|a| a == "--help" || a == "-h") {
        print!("{HELP}");
        return ExitCode::SUCCESS;
    }

    let report = run_core();
    if args.iter().any(|a| a == "--json") {
        match serde_json::to_string_pretty(&report) {
            Ok(json) => println!("{json}"),
            Err(error) => eprintln!("zero-doctor: could not serialize the report: {error}"),
        }
    } else {
        print!("{}", report.render_human());
    }
    ExitCode::SUCCESS
}
