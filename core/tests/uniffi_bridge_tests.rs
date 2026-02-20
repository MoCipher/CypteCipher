use crate::uniffi::{generate_mnemonic, first_receive_address, create_psbt, sign_psbt};

#[test]
fn uniffi_generate_and_address() {
    let m = generate_mnemonic(128);
    assert!(!m.is_empty());
    let addr = first_receive_address(&m);
    assert!(!addr.is_empty());
}

#[test]
fn uniffi_psbt_roundtrip_mock() {
    let m = generate_mnemonic(128);
    let addr = first_receive_address(&m);
    assert!(!addr.is_empty());
    let psbt = create_psbt(&m, &addr, 1000);
    assert!(!psbt.is_empty());
    let signed = sign_psbt(&m, &psbt);
    assert!(!signed.is_empty());
}
