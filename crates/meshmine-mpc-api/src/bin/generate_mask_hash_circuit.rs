use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::Path;

use meshmine_mpc_api::mask_hash_circuit::MaskHashCircuit;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let circuit = MaskHashCircuit::build();
    let rendered = circuit.bristol_string();
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    match arguments.as_slice() {
        [] => {
            let mut output = io::BufWriter::new(io::stdout().lock());
            output.write_all(rendered.as_bytes())?;
            output.flush()?;
        }
        [flag, path] if flag == "--out" => write_new(Path::new(path), rendered.as_bytes())?,
        _ => return Err("usage: generate_mask_hash_circuit [--out NEW_FILE]".into()),
    }
    Ok(())
}

fn write_new(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut output = OpenOptions::new().write(true).create_new(true).open(path)?;
    output.write_all(bytes)?;
    output.sync_all()
}
