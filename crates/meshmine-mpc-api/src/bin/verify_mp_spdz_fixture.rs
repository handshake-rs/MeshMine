//! Test-only end-to-end verifier for the reviewed three-party MP-SPDZ fixture.
//!
//! This deliberately reads every party output in one process to prove the
//! conformance run. Production members must instead call
//! `import_local_setup_output` independently with only their own output file.

use std::{env, path::PathBuf};

use ed25519_dalek::SigningKey;
use meshmine_mpc_api::{
    DeterministicVssBackend, MpcBackend, SessionPhase, SetupRequest, TimedOpeningGate,
    distributed::{
        ArtifactAllowlist, MpSpdzArtifactPaths, MpSpdzLocalOutput, assemble_distributed_setup,
        import_local_setup_output, load_local_opening, reviewed_three_party_fixture_manifest,
    },
};
use meshmine_storage::MemoryStore;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args_os();
    let _binary = args.next();
    let Some(root) = args.next() else {
        return Err("usage: verify_mp_spdz_fixture MP_SPDZ_ROOT".into());
    };
    if args.next().is_some() {
        return Err("usage: verify_mp_spdz_fixture MP_SPDZ_ROOT".into());
    }
    let root = PathBuf::from(root);
    let program = "meshmine_distributed_setup-16-8-3-2";
    let manifest = reviewed_three_party_fixture_manifest();
    let verified = manifest.verify_files(MpSpdzArtifactPaths {
        setup_source: &root.join("Programs/Source/meshmine_distributed_setup.mpc"),
        mask_hash_circuit: &root.join("Programs/Circuits/meshmine_mask_hash.txt"),
        bytecode: &root.join(format!("Programs/Bytecode/{program}-0.bc")),
        schedule: &root.join(format!("Programs/Schedules/{program}.sch")),
        runtime_binary: &root.join("mascot-party.x"),
        runtime_library: &root.join("libSPDZ.so"),
    })?;
    let allowlist = ArtifactAllowlist::new([verified.artifact_id()]);
    let artifact = allowlist.authorize(&verified)?;

    let outputs: Vec<_> = (0..3)
        .map(|party| {
            MpSpdzLocalOutput::read(&root.join(format!("Player-Data/Binary-Output-P{party}-0")))
        })
        .collect::<Result<_, _>>()?;
    let mut keys = [
        SigningKey::from_bytes(&[1; 32]),
        SigningKey::from_bytes(&[2; 32]),
        SigningKey::from_bytes(&[3; 32]),
    ];
    keys.sort_by_key(|key| key.verifying_key().to_bytes());
    let members: Vec<_> = keys
        .iter()
        .map(|key| key.verifying_key().to_bytes())
        .collect();
    let request = SetupRequest {
        protocol_version: 2,
        network_id: 0,
        lane_id: 0,
        session_sequence: 1,
        parent_hash: outputs[0].parent_hash,
        leading_zero_prefix_q: outputs[0].leading_zero_prefix_q,
        blind_band_bits_d: outputs[0].blind_band_bits_d,
        threshold: outputs[0].threshold,
        timed_open_after_ms: 0,
        deterministic_seed: [0; 32],
    };
    let stores: Vec<_> = (0..3).map(|_| MemoryStore::default()).collect();
    let contributions: Vec<_> = (0..3)
        .map(|party| {
            import_local_setup_output(
                &stores[party],
                &request,
                &members,
                &keys[party],
                party as u8,
                &outputs[party],
                &artifact,
            )
        })
        .collect::<Result<_, _>>()?;
    let assembled = assemble_distributed_setup(&request, &members, &contributions, &artifact)?;
    let openings: Vec<_> = stores
        .iter()
        .zip(&members)
        .map(|(store, member)| load_local_opening(store, &assembled.setup.session_binding, member))
        .collect::<Result<_, _>>()?;
    let backend = DeterministicVssBackend::new(&stores[0]);
    let opened = backend.timed_open(
        &assembled.setup,
        &openings,
        &TimedOpeningGate {
            phase: SessionPhase::Opening,
            timed_open_after_ms: 0,
            accepted_boundary_fixed: true,
        },
        0,
    )?;

    println!("mp_spdz_fixture=verified");
    println!("artifact_id={}", hex::encode(assembled.artifact_id));
    println!(
        "session_binding={}",
        hex::encode(assembled.setup.session_binding)
    );
    println!("mask_hash={}", hex::encode(assembled.setup.mask_hash));
    println!("opened_mask={}", hex::encode(opened.mask));
    println!("members={} threshold={}", members.len(), request.threshold);
    println!("private_output_bytes_per_member=824");
    println!("production_eligible=false");
    Ok(())
}
