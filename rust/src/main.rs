use hex::FromHex;
use kaspa_addresses::Address;
use kaspa_hashes::PersonalMessageSigningHash;
use kaspa_wallet_core::message::{
    PersonalMessage, SignMessageOptions, sign_message, verify_message,
};
use secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};

fn main() {
    let sk_hex = "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF";
    let sk_bytes: [u8; 32] = <[u8; 32]>::from_hex(sk_hex).expect("32-byte hex");
    let sk = SecretKey::from_slice(&sk_bytes).unwrap();

    let secp = Secp256k1::new();
    let kp = Keypair::from_secret_key(&secp, &sk);
    let (xonly, _parity) = XOnlyPublicKey::from_keypair(&kp);

    println!("pk: {}", hex::encode(xonly.serialize()));

    let kaspa_address = Address::new(
        kaspa_addresses::Prefix::Mainnet,
        kaspa_addresses::Version::PubKey,
        &xonly.serialize(),
    );

    println!("kaspa address: {}", kaspa_address);

    let msg = PersonalMessage("hello world");

    let mut hasher = PersonalMessageSigningHash::new();
    hasher.write(msg.clone());
    let hash = hasher.finalize();

    println!("message digest: {}", hex::encode(hash.as_bytes()));

    let sig = sign_message(
        &msg,
        &sk.secret_bytes(),
        // for debug purpose
        &SignMessageOptions { no_aux_rand: false },
    )
    .expect("sign");

    println!("signature: {}", hex::encode(sig.as_slice()));

    verify_message(&msg, &sig, &xonly).expect("verify");

    println!("✅ signature ok, sig len = {}", sig.len());
}
