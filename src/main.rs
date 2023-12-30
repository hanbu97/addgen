use std::sync::{atomic::AtomicU64, Arc};

use core::sync::atomic::Ordering;
use packed_simd::u8x32;
use rand::Rng;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sha3::{Digest, Keccak256};

fn check_leading_zeros_simd(addresses: &[Vec<u8>], leading_zeros_half: usize) -> bool {
    for addr in addresses {
        if addr.iter().take(leading_zeros_half).all(|&x| x == 0) {
            return true;
        }
    }
    false
}

#[derive(Debug)]
pub struct Address {
    pub address: Vec<u8>,
    pub private_key: Vec<u8>,
}

pub fn genaddress(rng: &mut impl Rng) -> Address {
    let private_key: [u8; 32] = rng.gen();
    let secret_key = SecretKey::from_slice(&private_key).expect("Unable to parse the secret key");

    let secp: Secp256k1<secp256k1::All> = Secp256k1::new();
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    let public_key_serialized = public_key.serialize_uncompressed();

    let public_key_hash = Keccak256::digest(&public_key_serialized[1..]);
    let address = &public_key_hash[12..];

    Address {
        address: address.to_vec(),
        private_key: private_key.to_vec(),
    }
}

fn main() {
    let count = AtomicU64::new(0);
    let count = Arc::new(count);

    let threads = num_cpus::get();
    let core_ids = core_affinity::get_core_ids().unwrap();

    let leading_zeros_half = 3;

    crossbeam::thread::scope(|s| {
        for i in 0..threads {
            let count_clone = Arc::clone(&count);
            let core_id = core_ids[i % core_ids.len()];

            s.spawn(move |_| {
                core_affinity::set_for_current(core_id);
                let mut rng = rand::thread_rng();
                let mut address_batch = Vec::new();
                let mut prev_batch = Vec::new();

                loop {
                    let address = genaddress(&mut rng);
                    address_batch.push(address.address.clone());
                    prev_batch.push(address.private_key.clone());

                    if address_batch.len() == 32 {
                        if check_leading_zeros_simd(&address_batch, leading_zeros_half) {
                            for (addr, prev) in address_batch.iter().zip(prev_batch) {
                                if addr.iter().take(leading_zeros_half).all(|&x| x == 0) {
                                    println!("Address: 0x{}", hex::encode(&addr));
                                    println!("Private key: {:?}", hex::encode(&prev));
                                }
                            }
                            std::process::exit(0);
                            // for addr in &address_batch {
                            //     println!("Address: 0x{}", hex::encode(addr));
                            // }
                        }
                        address_batch.clear();
                    }

                    count_clone.fetch_add(1, Ordering::SeqCst);
                    if count_clone.load(Ordering::Relaxed) % 1000000 == 0 {
                        println!("count: {}", count_clone.load(Ordering::SeqCst));
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
