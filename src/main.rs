//! Quantum-Safe Multi-Sig Wallet with HSM Support
//! Uses SPHINCS+ for quantum-safe signatures and PKCS#11 HSM for key storage.

use pqcrypto_sign::sphincs::{self, PublicKey, Signature};
use pkcs11::{Ctx, types::{CK_ATTRIBUTE_TYPE, CKF_RW_SESSION, CKF_SERIAL_SESSION}};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use serde::{Serialize, Deserialize};
use clap::{Arg, Command};

#[derive(Debug, Serialize, Deserialize)]
pub struct QuantumSafeWallet {
    owners: HashMap<String, PublicKey>,
    threshold: usize,
    signatures: HashMap<String, Signature>,
}

impl QuantumSafeWallet {
    pub fn new(owners: HashMap<String, PublicKey>, threshold: usize) -> Self {
        assert!(threshold <= owners.len(), "Threshold must be <= owner count");
        Self {
            owners,
            threshold,
            signatures: HashMap::new(),
        }
    }

    /// Sign a transaction using HSM
    pub fn sign_transaction_with_hsm(&mut self, owner: &str, hsm: &Ctx, message: &[u8], pin: &str) {
        if let Some(pub_key) = self.owners.get(owner) {
            let session = hsm.open_session(0, CKF_SERIAL_SESSION | CKF_RW_SESSION).unwrap();
            hsm.login(session, pin).unwrap();

            let signature = hsm.sign(session, message).unwrap();
            self.signatures.insert(owner.to_string(), signature);

            hsm.logout(session).unwrap();
            println!("{} signed the transaction using HSM.", owner);
        }
    }

    /// Verify the transaction by checking if enough valid signatures exist
    pub fn verify_transaction(&self, message: &[u8]) -> bool {
        let valid_sigs = self.signatures.iter().filter(|(owner, sig)| {
            if let Some(pub_key) = self.owners.get(*owner) {
                sphincs::verify(message, sig, pub_key).is_ok()
            } else {
                false
            }
        }).count();

        valid_sigs >= self.threshold
    }
}

fn save_wallet(wallet: &QuantumSafeWallet) {
    let serialized = serde_json::to_string(wallet).unwrap();
    let mut file = OpenOptions::new().write(true).create(true).open("wallet.json").unwrap();
    file.write_all(serialized.as_bytes()).unwrap();
}

fn load_wallet() -> QuantumSafeWallet {
    let mut file = File::open("wallet.json").unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();
    serde_json::from_str(&contents).unwrap()
}

fn main() {
    let matches = Command::new("Quantum-Safe Multi-Sig Wallet")
        .version("1.0")
        .author("Orly")
        .about("A quantum-safe multi-signature wallet with HSM support")
        .arg(Arg::new("sign")
            .long("sign")
            .takes_value(true)
            .help("Sign a transaction using HSM"))
        .arg(Arg::new("verify")
            .long("verify")
            .help("Verify a transaction"))
        .get_matches();

    let (pk1, sk1) = sphincs::keypair();
    let (pk2, sk2) = sphincs::keypair();
    let (pk3, sk3) = sphincs::keypair();

    let mut owners = HashMap::new();
    owners.insert("Alice".to_string(), pk1.clone());
    owners.insert("Bob".to_string(), pk2.clone());
    owners.insert("Charlie".to_string(), pk3.clone());

    let mut wallet = QuantumSafeWallet::new(owners, 2);

    let transaction = b"Transfer 10 coins";

    if let Some(owner) = matches.value_of("sign") {
        let hsm = Ctx::new("/usr/lib/softhsm/libsofthsm2.so").unwrap();
        let hsm_pin = "1234"; // Replace with secure pin management

        wallet.sign_transaction_with_hsm(owner, &hsm, transaction, hsm_pin);
        save_wallet(&wallet);
    }

    if matches.is_present("verify") {
        if wallet.verify_transaction(transaction) {
            println!("Transaction Approved!");
        } else {
            println!("Transaction Rejected!");
        }
    }
}

