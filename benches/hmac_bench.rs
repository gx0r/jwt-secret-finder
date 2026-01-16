use std::time::{Duration, Instant};

const ITERATIONS: u64 = 5_000_000;
const MESSAGE: &[u8] = b"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9";

fn bench_ring() -> Duration {
    use ring::hmac;

    let key = hmac::Key::new(hmac::HMAC_SHA256, b"secret");

    let start = Instant::now();
    for _ in 0..ITERATIONS {
        let _ = hmac::sign(&key, MESSAGE);
    }
    start.elapsed()
}

fn bench_aws_lc() -> Duration {
    use aws_lc_rs::hmac;

    let key = hmac::Key::new(hmac::HMAC_SHA256, b"secret");

    let start = Instant::now();
    for _ in 0..ITERATIONS {
        let _ = hmac::sign(&key, MESSAGE);
    }
    start.elapsed()
}

fn main() {
    println!("HMAC-SHA256 Benchmark ({} iterations)\n", ITERATIONS);
    println!("Message size: {} bytes", MESSAGE.len());
    println!();

    // Warmup
    println!("Warming up...");
    for _ in 0..3 {
        let _ = bench_ring();
        let _ = bench_aws_lc();
    }

    // Run benchmarks multiple times
    const RUNS: usize = 5;
    let mut ring_times = Vec::with_capacity(RUNS);
    let mut aws_times = Vec::with_capacity(RUNS);

    println!("Running {} benchmark rounds...\n", RUNS);

    for i in 0..RUNS {
        print!("Round {}... ", i + 1);

        let ring_time = bench_ring();
        let aws_time = bench_aws_lc();

        ring_times.push(ring_time);
        aws_times.push(aws_time);

        println!("ring: {:?}, aws-lc-rs: {:?}", ring_time, aws_time);
    }

    // Calculate stats
    let ring_avg: Duration = ring_times.iter().sum::<Duration>() / RUNS as u32;
    let aws_avg: Duration = aws_times.iter().sum::<Duration>() / RUNS as u32;

    let ring_min = ring_times.iter().min().unwrap();
    let aws_min = aws_times.iter().min().unwrap();

    println!("\n========== RESULTS ==========");
    println!("ring 0.17:");
    println!("  Average: {:?}", ring_avg);
    println!("  Best:    {:?}", ring_min);
    println!("  Rate:    {:.2} M ops/sec", ITERATIONS as f64 / ring_avg.as_secs_f64() / 1_000_000.0);

    println!("\naws-lc-rs:");
    println!("  Average: {:?}", aws_avg);
    println!("  Best:    {:?}", aws_min);
    println!("  Rate:    {:.2} M ops/sec", ITERATIONS as f64 / aws_avg.as_secs_f64() / 1_000_000.0);

    println!("\n========== COMPARISON ==========");
    let ratio = ring_avg.as_secs_f64() / aws_avg.as_secs_f64();
    if ratio > 1.0 {
        println!("aws-lc-rs is {:.1}% faster than ring", (ratio - 1.0) * 100.0);
    } else {
        println!("ring is {:.1}% faster than aws-lc-rs", (1.0 / ratio - 1.0) * 100.0);
    }
}
