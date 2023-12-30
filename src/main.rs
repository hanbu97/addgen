use std::sync::{atomic::AtomicU64, Arc};

use core::sync::atomic::Ordering;
use rand::Rng;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sha3::{Digest, Keccak256};

#[derive(Debug)]
pub struct Address {
    pub address: String,
    pub private_key: String,
}

pub fn genaddress() -> Address {
    let mut rng = rand::thread_rng();
    let private_key: [u8; 32] = rng.gen();
    let secret_key = SecretKey::from_slice(&private_key).expect("Unable to parse the secret key");

    let secp: Secp256k1<secp256k1::All> = Secp256k1::new();
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    let public_key_serialized = public_key.serialize_uncompressed();

    let public_key_hash = Keccak256::digest(&public_key_serialized[1..]);
    let address = &public_key_hash[12..];

    Address {
        address: hex::encode(address),
        private_key: hex::encode(private_key),
    }
}

fn main() {
    let count = AtomicU64::new(0);
    let count = Arc::new(count);

    let threads = num_cpus::get();
    let core_ids = core_affinity::get_core_ids().unwrap();

    crossbeam::thread::scope(|s| {
        for i in 0..threads {
            let count_clone = Arc::clone(&count);
            let core_id = core_ids[i % core_ids.len()];

            s.spawn(move |_| {
                core_affinity::set_for_current(core_id);
                loop {
                    let address = genaddress();
                    if address.address.starts_with("00000000") {
                        println!("Address: 0x{}", address.address);
                        println!("Private key: {:?}", address.private_key);
                        std::process::exit(0);
                    }

                    count_clone.fetch_add(1, Ordering::SeqCst);
                    if count_clone.load(Ordering::Relaxed) % 1000000 == 0 {
                        println!("count: {}", count_clone.load(Ordering::SeqCst));
                    }
                }
            });
        }
    })
    .unwrap();
}

#[test]
fn test_num_cpus() {
    println!("num_cpus: {}", num_cpus::get());
}
