use std::fs;
use std::{env, error::Error, process};

use meshmine_sim::{
    OverlayTestnetConfig, default_load_assumptions, derive_capture_profile,
    render_overlay_explorer, run_overlay_testnet,
};

fn main() {
    if let Err(error) = run() {
        eprintln!("meshmine-sim: {error}");
        process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let arguments: Vec<_> = env::args().skip(1).collect();
    match arguments.first().map(String::as_str) {
        Some("capture") => capture(&arguments[1..]),
        Some("overlay") => overlay(&arguments[1..]),
        _ => Err("usage: meshmine-sim capture [BITS_HEX] | overlay [SESSIONS] --output FILE [--explorer FILE]".into()),
    }
}

fn capture(arguments: &[String]) -> Result<(), Box<dyn Error>> {
    let bits = arguments
        .first()
        .map(|value| value.trim_start_matches("0x"))
        .map(|value| u32::from_str_radix(value, 16))
        .transpose()?
        .unwrap_or(0x1925_ae67);
    println!("bits       d   p   q   shares/block   shares/sec   ingress B/s");
    for blind_bits in 8..=16 {
        let profile = derive_capture_profile(bits, blind_bits, default_load_assumptions())?;
        println!(
            "{bits:#010x} {:>3} {:>3} {:>3} {:>14} {:>12} {:>13}",
            blind_bits,
            profile.leading_zero_bits_p,
            profile.leading_zero_prefix_q,
            profile.load.capture_shares_per_hns_block.decimal(3),
            profile.load.capture_shares_per_second.decimal(6),
            profile.load.ingress_bytes_per_second.decimal(3),
        );
    }
    Ok(())
}

fn overlay(arguments: &[String]) -> Result<(), Box<dyn Error>> {
    let session_count = arguments
        .first()
        .filter(|argument| !argument.starts_with("--"))
        .map(|value| value.parse())
        .transpose()?
        .unwrap_or(1_000);
    let output = argument(arguments, "--output")?;
    let transcript = run_overlay_testnet(OverlayTestnetConfig {
        session_count,
        committee_members: 5,
        opening_threshold: 3,
        seed: [77; 32],
    })?;
    fs::write(output, serde_json::to_vec_pretty(&transcript)?)?;
    if let Some(path) = optional_argument(arguments, "--explorer") {
        fs::write(path, render_overlay_explorer(&transcript))?;
    }
    println!("status=overlay-simulated");
    println!("sessions={}", transcript.session_count);
    println!("accepted_winners={}", transcript.summary.accepted_winners);
    println!("recovered_winners={}", transcript.summary.recovered_winners);
    println!(
        "unrecoverable_under_assumption={}",
        transcript.summary.unrecoverable_winners_under_assumption
    );
    println!("final_event_hash={}", transcript.summary.final_event_hash);
    println!("public_deployment_verified=false");
    Ok(())
}

fn argument<'a>(arguments: &'a [String], name: &str) -> Result<&'a str, Box<dyn Error>> {
    optional_argument(arguments, name).ok_or_else(|| format!("missing {name}").into())
}

fn optional_argument<'a>(arguments: &'a [String], name: &str) -> Option<&'a str> {
    arguments
        .windows(2)
        .find(|pair| pair[0] == name)
        .map(|pair| pair[1].as_str())
}
