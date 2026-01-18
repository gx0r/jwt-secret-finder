use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use clap::Parser;
use ring::hmac;
use std::process::exit;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

#[derive(Parser, Debug)]
#[command(name = "jwtc", about = "JWT secret brute-forcer")]
struct Args {
    #[arg(
        short = 't',
        long = "token",
        help = "the JWT token",
        default_value = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
            eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.\
            cAOIAifu3fykvhkHpbuhbvtH807-Z2rI1FS3vX1XMjE"
    )]
    token: String,

    #[arg(
        short = 'a',
        long = "alphabet",
        help = "the alphabet",
        default_value = "eariotnslcudpmhgbfywkvxzjqEARIOTNSLCUDPMHGBFYWKVXZJQ0123456789"
    )]
    alphabet: String,

    #[arg(
        short = 'x',
        long = "maxlength",
        help = "Maximum Length",
        default_value = "6"
    )]
    max_length: usize,
}

fn main() {
    let args = Args::parse();

    let parts: Vec<&str> = args.token.split('.').collect();
    if parts.len() != 3 {
        eprintln!("Invalid JWT token format");
        exit(1);
    }

    let presented_signature = URL_SAFE_NO_PAD
        .decode(parts[2])
        .expect("JWT signature Base64 decoding failed");

    let message_to_sign = format!("{}.{}", parts[0], parts[1]);

    println!("Token: {}", args.token);
    println!(
        "Alphabet: {} ({} chars)",
        args.alphabet,
        args.alphabet.len()
    );
    println!("Max length: {}", args.max_length);
    println!();

    let result = search_secret(
        args.alphabet.as_bytes(),
        args.max_length,
        &presented_signature,
        message_to_sign.as_bytes(),
    );

    if result.is_none() {
        exit(1);
    }
}

fn search_secret(alphabet: &[u8], max_length: usize, target_signature: &[u8], message: &[u8]) -> Option<Vec<u8>> {
    let found = AtomicBool::new(false);
    let num_threads = num_cpus::get();
    let result: std::sync::Mutex<Option<Vec<u8>>> = std::sync::Mutex::new(None);

    for len in 1..=max_length {
        if found.load(Ordering::Relaxed) {
            break;
        }
        println!("Checking length {}", len);

        let total: usize = alphabet.len().pow(len as u32);
        let chunk_size = (total + num_threads - 1) / num_threads;

        thread::scope(|s| {
            for thread_id in 0..num_threads {
                let start = thread_id * chunk_size;
                let end = (start + chunk_size).min(total);
                let found = &found;
                let result = &result;

                s.spawn(move || {
                    let mut buffer = [0u8; 64];

                    for idx in start..end {
                        if found.load(Ordering::Relaxed) {
                            return;
                        }

                        let mut n = idx;
                        for i in (0..len).rev() {
                            buffer[i] = alphabet[n % alphabet.len()];
                            n /= alphabet.len();
                        }

                        let secret = &buffer[..len];
                        let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
                        let tag = hmac::sign(&key, message);

                        if tag.as_ref() == target_signature {
                            println!("Found secret: {}", String::from_utf8_lossy(secret));
                            *result.lock().unwrap() = Some(secret.to_vec());
                            found.store(true, Ordering::SeqCst);
                            return;
                        }
                    }
                });
            }
        });
    }

    let res = result.lock().unwrap().take();
    if res.is_none() {
        println!("Secret not found");
    }
    res
}

#[cfg(test)]
mod test {
    use super::*;
    use std::time::Instant;

    #[test]
    fn check_works() {
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
                     eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.\
                     cAOIAifu3fykvhkHpbuhbvtH807-Z2rI1FS3vX1XMjE";
        let parts: Vec<&str> = token.split('.').collect();
        let signature = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        let message = format!("{}.{}", parts[0], parts[1]);

        let start = Instant::now();
        search_secret(b"Sn1f", 5, &signature, message.as_bytes());
        eprintln!("Runtime: {:?}", start.elapsed());
    }

    #[test]
    fn check_pass() {
        // JWT signed with secret "pass"
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
                     eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.\
                     -aPN48Dhqq2o2JvIbH0VCZCHhvNVNXC7a0PTmOce-Kk";
        let parts: Vec<&str> = token.split('.').collect();
        let signature = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        let message = format!("{}.{}", parts[0], parts[1]);

        let start = Instant::now();
        search_secret(b"abcdefghijklmnopqrstuvwxyz", 4, &signature, message.as_bytes());
        eprintln!("Runtime: {:?}", start.elapsed());
    }

    #[test]
    fn check_secret() {
        // JWT signed with secret "secret"
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
                     eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.\
                     TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ";
        let parts: Vec<&str> = token.split('.').collect();
        let signature = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        let message = format!("{}.{}", parts[0], parts[1]);

        let start = Instant::now();
        search_secret(b"abcdefghijklmnopqrstuvwxyz", 6, &signature, message.as_bytes());
        eprintln!("Runtime: {:?}", start.elapsed());
    }
}
