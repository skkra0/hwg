use anyhow::Result;


use chacha20poly1305::{AeadInOut, ChaCha20Poly1305, Nonce, Tag};

pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;


pub fn encrypt<'a>(buf: &'a mut [u8], cipher: &ChaCha20Poly1305, nonce: chacha20poly1305::Nonce) -> Result<&'a [u8]>{
    let n = buf.len() - NONCE_LEN - TAG_LEN;
    let tag = cipher
        .encrypt_inout_detached(&nonce, b"", (&mut buf[..n]).into())?;

    buf[n..n+NONCE_LEN].copy_from_slice(nonce.as_slice());
    buf[n+NONCE_LEN..].copy_from_slice(&tag);

    Ok(buf)
}

pub fn decrypt<'a>(buf: &'a mut [u8], cipher: &ChaCha20Poly1305) -> Result<(&'a [u8], Nonce)> {
    let n = buf.len() - NONCE_LEN - TAG_LEN;
    let (msg, rest) = buf.split_at_mut(n);

    // pull out nonce  and tag
    let mut nonce = Nonce::default();
    nonce.copy_from_slice(&rest[..NONCE_LEN]);

    let tag = Tag::try_from(&rest[NONCE_LEN..])?;

    // decrypt in place; on tag-verification failure, drop the packet
    cipher.decrypt_inout_detached(&nonce, b"", msg.into(), &tag)?;
    Ok((msg, nonce))
}

pub fn increment_nonce(mut nonce: Nonce) -> Nonce {
    for byte in nonce.iter_mut() {
       *byte = byte.wrapping_add(1);
       if *byte != 0 {
        break;
       } 
    }

    nonce
}