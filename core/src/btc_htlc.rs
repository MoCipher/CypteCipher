use bitcoin::blockdata::script::Script;
use bitcoin::util::key::PublicKey;
use bitcoin::hashes::{hash160, sha256, Hash};
use bitcoin::blockdata::opcodes::all::*;
use bitcoin::network::constants::Network;
use bitcoin::util::address::Address;

/// Build a simple HTLC redeem script (timelock refund + hashlock)
/// script: 
/// OP_IF
///   OP_SIZE <32> OP_EQUALVERIFY OP_SHA256 <hash> OP_EQUALVERIFY OP_DUP OP_HASH160 <recipient_hash160> OP_EQUALVERIFY OP_CHECKSIG
/// OP_ELSE
///   <locktime> OP_CHECKLOCKTIMEVERIFY OP_DROP OP_DUP OP_HASH160 <refund_hash160> OP_EQUALVERIFY OP_CHECKSIG
/// OP_ENDIF

pub fn build_htlc_redeem_script(hash: &[u8;32], recipient_pub: &PublicKey, refund_pub: &PublicKey, locktime: u32) -> Script {
    let recipient_hash = hash160::Hash::hash(&recipient_pub.to_bytes());
    let refund_hash = hash160::Hash::hash(&refund_pub.to_bytes());

    let mut builder = Script::builder();

    builder = builder
        .push_opcode(OP_IF)
        .push_opcode(OP_SIZE)
        .push_int(32)
        .push_opcode(OP_EQUALVERIFY)
        .push_opcode(OP_SHA256)
        .push_slice(hash)
        .push_opcode(OP_EQUALVERIFY)
        .push_opcode(OP_DUP)
        .push_opcode(OP_HASH160)
        .push_slice(&recipient_hash.into_inner())
        .push_opcode(OP_EQUALVERIFY)
        .push_opcode(OP_CHECKSIG)
        .push_opcode(OP_ELSE)
        .push_int(locktime as i64)
        .push_opcode(OP_CHECKLOCKTIMEVERIFY)
        .push_opcode(OP_DROP)
        .push_opcode(OP_DUP)
        .push_opcode(OP_HASH160)
        .push_slice(&refund_hash.into_inner())
        .push_opcode(OP_EQUALVERIFY)
        .push_opcode(OP_CHECKSIG)
        .push_opcode(OP_ENDIF);

    builder.into_script()
}

pub fn htlc_p2wsh_address(redeem: &Script, network: Network) -> Address {
    Address::p2wsh(&redeem.to_v0_p2wsh(), network).expect("p2wsh address")
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::Secp256k1;
    use bitcoin::secp256k1::PublicKey as SecpPub;
    use secp256k1::SecretKey;
    use rand::rngs::OsRng;
    use rand::RngCore;

    #[test]
    fn build_htlc_script_and_address() {
        let secp = Secp256k1::new();
        let mut rng = OsRng::default();
        let sk1 = SecretKey::new(&mut rng);
        let sk2 = SecretKey::new(&mut rng);
        let pk1 = SecpPub::from_secret_key(&secp, &sk1);
        let pk2 = SecpPub::from_secret_key(&secp, &sk2);
        let mut hash = [0u8;32];
        rng.fill_bytes(&mut hash);
        let script = build_htlc_redeem_script(&hash, &PublicKey{ key: pk1, compressed: true }, &PublicKey{ key: pk2, compressed: true }, 500);
        assert!(script.len() > 0);
    }
}
