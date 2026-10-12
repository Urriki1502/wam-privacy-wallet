//! Fixed public fixtures only. No input key/note, signing or plaintext output.
use std::io::{self, Read};
use halo2_proofs::pasta::Fp;
use wam_privacy_halo2_prototype::note_encryption::{
    encrypt_note, EncryptedNote, NoteAad, NotePlaintext, ShieldedKeyBundle,
};

fn exercise(role: &str) -> Result<(), ()> {
    // These seeds are public test constants, never wallet material. The upstream
    // bundle derives its internal hierarchy; no spend-authority or signer API is
    // called here. Drop the bundle before handling the selected viewing role.
    let bundle = ShieldedKeyBundle::derive([0x42; 32]);
    let address = bundle.address();
    let incoming = bundle.incoming_viewing_key();
    let audit = bundle.audit_viewing_key();
    drop(bundle);
    let note = NotePlaintext {
        value: 123456, recipient_tag: address.recipient_tag,
        spend_authority_tag: address.spend_authority_tag,
        rho: Fp::from(0x4444), rseed: Fp::from(0x5555),
        memo: b"PUBLIC WALLET HPKE FIXTURE".to_vec(),
    };
    let aad = NoteAad {
        network_id: 3, transaction_digest: [0x11; 32], output_index: 7,
        note_commitment: [0x22; 32], context_digest: [0x33; 32],
    };
    let encrypted = encrypt_note(&address, &note, &aad).map_err(|_| ())?;
    let decoded = EncryptedNote::decode(&encrypted.encode().map_err(|_| ())?).map_err(|_| ())?;
    let opened = match role {
        "incoming" => incoming.decrypt(&decoded, &aad),
        "audit" => audit.decrypt(&decoded, &aad),
        _ => return Err(()),
    }.map_err(|_| ())?;
    if opened != note { return Err(()); }
    drop(opened);
    let wrong = ShieldedKeyBundle::derive([0x99; 32]);
    if wrong.incoming_viewing_key().decrypt(&decoded, &aad).is_ok()
        || wrong.audit_viewing_key().decrypt(&decoded, &aad).is_ok() { return Err(()); }
    drop(wrong);
    let cross = EncryptedNote { recipient: decoded.audit.clone(), audit: decoded.recipient.clone() };
    if incoming.decrypt(&cross, &aad).is_ok() || audit.decrypt(&cross, &aad).is_ok() { return Err(()); }
    for field in 0..5 {
        let mut changed = aad.clone();
        match field {
            0 => changed.network_id ^= 1,
            1 => changed.transaction_digest[0] ^= 1,
            2 => changed.output_index ^= 1,
            3 => changed.note_commitment[0] ^= 1,
            _ => changed.context_digest[0] ^= 1,
        }
        if incoming.decrypt(&decoded, &changed).is_ok() || audit.decrypt(&decoded, &changed).is_ok() { return Err(()); }
    }
    let mut changed = decoded.clone(); changed.recipient.ciphertext[0] ^= 1;
    if incoming.decrypt(&changed, &aad).is_ok() { return Err(()); }
    let mut changed = decoded.clone(); changed.audit.ciphertext[0] ^= 1;
    if audit.decrypt(&changed, &aad).is_ok() { return Err(()); }
    let encoded = decoded.encode().map_err(|_| ())?;
    let mut trailing = encoded.clone(); trailing.push(0);
    if EncryptedNote::decode(&trailing).is_ok() || EncryptedNote::decode(&encoded[..encoded.len()-1]).is_ok() { return Err(()); }
    let mut version = encoded.clone(); version[4..6].copy_from_slice(&2u16.to_le_bytes());
    if EncryptedNote::decode(&version).is_ok() { return Err(()); }
    let second = encrypt_note(&address, &note, &aad).map_err(|_| ())?;
    if decoded.recipient.encapped_key == second.recipient.encapped_key
        || decoded.audit.encapped_key == second.audit.encapped_key { return Err(()); }
    Ok(())
}

fn run() -> Result<(), ()> {
    if std::env::args().len() != 1 { return Err(()); }
    let mut request = Vec::new();
    io::stdin().take(129).read_to_end(&mut request).map_err(|_| ())?;
    let role = match request.as_slice() {
        b"PUBLIC_SYNTHETIC_HPKE_V1:incoming\n" => "incoming",
        b"PUBLIC_SYNTHETIC_HPKE_V1:audit\n" => "audit",
        _ => return Err(()),
    };
    exercise(role)?;
    println!("{{\"source_commit\":\"db3d2dcaa540f1129d540101813b761167d33174\",\"role\":\"{role}\",\"negative_checks\":14,\"pointer_bits\":{},\"evidence\":\"PUBLIC_HPKE_FIXTURE_EXECUTED_UNTRUSTED\",\"external_review_complete\":false,\"runtime_authenticated\":false,\"spend_authorized\":false,\"sign_allowed\":false,\"broadcast_allowed\":false}}", usize::BITS);
    Ok(())
}

fn main() {
    if run().is_err() { std::process::exit(2); }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn incoming_fixture_executes_actual_hpke() { assert!(exercise("incoming").is_ok()); }
    #[test] fn audit_fixture_executes_actual_hpke() { assert!(exercise("audit").is_ok()); }
    #[test] fn unknown_role_denied() { assert!(exercise("spend").is_err()); }
}
