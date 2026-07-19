use std::error::Error;
use std::io::{self, BufWriter, Write};

use ed25519_dalek::SigningKey;
use meshmine_hns::blake2b_256;
use meshmine_mpc_api::{
    MpcBackend, ResearchVssBackend, SessionPhase, SetupRequest, TimedOpeningGate,
};
use meshmine_storage::MemoryStore;

fn main() {
    if let Err(error) = run() {
        eprintln!("generate_opened_vectors: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let count = std::env::args()
        .nth(1)
        .map(|value| value.parse::<u64>())
        .transpose()?
        .unwrap_or(10_000);
    let store = MemoryStore::default();
    let backend = ResearchVssBackend::new(&store);
    let members = vec![
        SigningKey::from_bytes(&[1; 32]),
        SigningKey::from_bytes(&[2; 32]),
        SigningKey::from_bytes(&[3; 32]),
    ];
    let stdout = io::stdout();
    let mut output = BufWriter::new(stdout.lock());

    for index in 0..count {
        let counter = index.to_le_bytes();
        let parent_hash = blake2b_256(&[b"meshmine/mpc-vector-parent/v2", &counter]);
        let deterministic_seed = blake2b_256(&[b"meshmine/mpc-vector-seed/v2", &counter]);
        let request = SetupRequest {
            protocol_version: 2,
            network_id: 2,
            lane_id: 0,
            session_sequence: index + 1,
            parent_hash,
            leading_zero_prefix_q: 8,
            blind_band_bits_d: 8,
            threshold: 2,
            timed_open_after_ms: 1,
            deterministic_seed,
        };
        let setup = backend.setup(&request, &members)?;
        let openings = setup
            .members
            .iter()
            .take(2)
            .map(|member| backend.load_opening(&setup.session_binding, member))
            .collect::<Result<Vec<_>, _>>()?;
        let opened = backend.timed_open(
            &setup,
            &openings,
            &TimedOpeningGate {
                phase: SessionPhase::Opening,
                timed_open_after_ms: 1,
                accepted_boundary_fixed: true,
            },
            1,
        )?;
        writeln!(
            output,
            "{index}\t{}\t{}\t{}\t{}\t{}",
            hex::encode(parent_hash),
            hex::encode(opened.mask),
            hex::encode(setup.mask_hash),
            setup.leading_zero_prefix_q,
            setup.blind_band_bits_d,
        )?;
    }
    output.flush()?;
    Ok(())
}
