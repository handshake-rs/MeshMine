//! Test-only input preparer for the reviewed MP-SPDZ fast-evaluation fixture.
//!
//! It centrally reconstructs the already-openable conformance mask solely to
//! create deterministic winner/loss public inputs. Production code must never
//! collect setup outputs this way.

use std::{
    env,
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
};

use meshmine_mpc_api::distributed::{MpSpdzLocalOutput, render_parent_public_input};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args_os();
    let _binary = args.next();
    let Some(root) = args.next() else {
        return Err("usage: prepare_mp_spdz_fast_fixture MP_SPDZ_ROOT winner|loss".into());
    };
    let Some(case) = args.next() else {
        return Err("usage: prepare_mp_spdz_fast_fixture MP_SPDZ_ROOT winner|loss".into());
    };
    if args.next().is_some() {
        return Err("usage: prepare_mp_spdz_fast_fixture MP_SPDZ_ROOT winner|loss".into());
    }
    let root = PathBuf::from(root);
    let case = case.to_str().ok_or("case must be UTF-8")?;
    if case != "winner" && case != "loss" {
        return Err("case must be winner or loss".into());
    }
    let outputs: Vec<_> = (0..3)
        .map(|party| {
            MpSpdzLocalOutput::read(&root.join(format!("Player-Data/Binary-Output-P{party}-0")))
        })
        .collect::<Result<_, _>>()?;
    if outputs[1..].iter().any(|output| {
        output.parent_hash != outputs[0].parent_hash
            || output.mask_hash != outputs[0].mask_hash
            || output.leading_zero_prefix_q != outputs[0].leading_zero_prefix_q
            || output.blind_band_bits_d != outputs[0].blind_band_bits_d
            || output.members != outputs[0].members
            || output.threshold != outputs[0].threshold
    }) {
        return Err("setup public outputs differ".into());
    }
    let mask = reconstruct_two(1, &outputs[0].local_share, 2, &outputs[1].local_share);
    let raw_share_hash = if case == "winner" { mask } else { [0xff; 32] };
    let network_target = [0; 32];

    let program = "meshmine_fast_eval-16-8-3-2-1-2";
    let mut public = String::new();
    public.push_str(&render_parent_public_input(&outputs[0].parent_hash));
    public.push_str(&render_parent_public_input(&outputs[0].mask_hash));
    public.push_str(&render_parent_public_input(&raw_share_hash));
    public.push_str(&render_parent_public_input(&network_target));
    write_new(
        &root.join(format!("Programs/Public-Input/{program}")),
        public.as_bytes(),
    )?;
    for (party, output) in outputs.iter().enumerate().take(2) {
        let mut input = String::new();
        for value in output.local_share {
            input.push_str(&value.to_string());
            input.push('\n');
        }
        write_new(
            &root.join(format!("Player-Data/Input-P{party}-0")),
            input.as_bytes(),
        )?;
    }
    println!("fast_fixture={case}");
    println!("program={program}");
    println!("raw_share_hash={}", hex::encode(raw_share_hash));
    println!("network_target={}", hex::encode(network_target));
    Ok(())
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.flush()?;
    file.sync_all()?;
    Ok(())
}

fn reconstruct_two(x0: u8, share0: &[u8; 32], x1: u8, share1: &[u8; 32]) -> [u8; 32] {
    let basis0 = gf_div(x1, x1 ^ x0);
    let basis1 = gf_div(x0, x0 ^ x1);
    std::array::from_fn(|index| gf_mul(share0[index], basis0) ^ gf_mul(share1[index], basis1))
}

fn gf_mul(mut left: u8, mut right: u8) -> u8 {
    let mut product = 0;
    while right != 0 {
        if right & 1 != 0 {
            product ^= left;
        }
        let high = left & 0x80;
        left <<= 1;
        if high != 0 {
            left ^= 0x1b;
        }
        right >>= 1;
    }
    product
}

fn gf_pow(mut value: u8, mut exponent: u8) -> u8 {
    let mut result = 1;
    while exponent != 0 {
        if exponent & 1 != 0 {
            result = gf_mul(result, value);
        }
        value = gf_mul(value, value);
        exponent >>= 1;
    }
    result
}

fn gf_div(numerator: u8, denominator: u8) -> u8 {
    gf_mul(numerator, gf_pow(denominator, 254))
}
