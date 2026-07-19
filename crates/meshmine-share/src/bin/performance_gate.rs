use std::error::Error;
use std::time::Instant;

use meshmine_share::benchmark::ShareValidationBenchmark;

fn main() {
    if let Err(error) = run() {
        eprintln!("performance_gate: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let fixture = ShareValidationBenchmark::new();
    for _ in 0..10 {
        fixture.validate_once()?;
    }
    let count = 1_000u64;
    let started = Instant::now();
    for _ in 0..count {
        fixture.validate_once()?;
    }
    let elapsed = started.elapsed().as_secs_f64();
    let rate = count as f64 / elapsed;
    println!("validated_shares={count}");
    println!("elapsed_seconds={elapsed:.6}");
    println!("shares_per_second_per_core={rate:.3}");
    println!("target_shares_per_second_per_core=100");
    if rate < 100.0 {
        return Err("MM-0001 share-validation prototype target was missed".into());
    }
    Ok(())
}
