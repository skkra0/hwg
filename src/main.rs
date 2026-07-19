use std::{net::SocketAddr, sync::Arc, env};

use anyhow::Result;
use chacha20poly1305::{AeadInOut, ChaCha20Poly1305, KeyInit, Nonce, Tag, aead::{Generate}};
use tokio::net::{UdpSocket};
use tun_rs::DeviceBuilder;

mod ipv4;
mod ping;

const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let self_addr = args[1].as_str();
    let peer_addr = format!("{}:51820", args[2]).parse::<SocketAddr>()?;

    let dev = DeviceBuilder::new()
        .name("utun7")
        .ipv4(self_addr, 24, None)
        .mtu(1400)
        .build_async()
        .unwrap();
    let sock = UdpSocket::bind("0.0.0.0:51820").await?;
    
    let key_bytes: &[u8] = b"\xe5r\xd8\xa5\x13oH\xf8\xa2r`\x17KX\xcc\xca\x0fN\xa5\xd5\xda\xd1\xad\xf5\xd1\xbc1S\xa2a\xc6v";
    let key: [u8; 32] = key_bytes.try_into().expect("Invalid key length");
    let cipher = ChaCha20Poly1305::new(&key.into());

    let dev = Arc::new(dev);
    let sock = Arc::new(sock);

    // outbound: TUN → UDP
    let dev_out = dev.clone();
    let sock_out = sock.clone();
    let cipher_out = cipher.clone();
    tokio::spawn(async move {
        // layout: [nonce | plaintext/ciphertext | tag]
        let mut buf = [0u8; NONCE_LEN + 1504 + TAG_LEN];
        loop {
            // read the IP packet in place, leaving room for the nonce prefix
            let n = dev_out.recv(&mut buf[NONCE_LEN..]).await.unwrap();
            let ip_header = match ipv4::Ipv4Header::try_from(&buf[NONCE_LEN..]) {
                Ok(h) => h,
                Err(e) =>{
                    eprintln!("{}", e);
                    continue;
                }
            };
            println!("{}", ip_header);

            // fresh random nonce every packet — never reused with this key
            let nonce = Nonce::generate();
            buf[..NONCE_LEN].copy_from_slice(nonce.as_slice());

            // encrypt the plaintext in place, get the detached 16-byte tag
            let tag = cipher_out
                .encrypt_inout_detached(&nonce, b"", (&mut buf[NONCE_LEN..NONCE_LEN + n]).into())
                .unwrap();

            // write the tag into the reserved space right after the ciphertext
            buf[NONCE_LEN + n..NONCE_LEN + n + TAG_LEN].copy_from_slice(&tag);

            sock_out
                .send_to(&buf[..NONCE_LEN + n + TAG_LEN], peer_addr)
                .await
                .unwrap();
        }
    });

    // inbound: UDP → TUN
    let cipher_in = cipher;
    tokio::spawn(async move {
        // layout: [nonce | ciphertext | tag]
        let mut buf = [0u8; NONCE_LEN + 1520 + TAG_LEN];
        loop {
            let (n, _from) = sock.recv_from(&mut buf).await.unwrap();

            // drop anything too short to contain a nonce + tag
            if n < NONCE_LEN + TAG_LEN {
                continue;
            }

            // pull the nonce out of the prefix (owned copy, so we can borrow buf mutably next)
            let mut nonce = Nonce::default();
            nonce.copy_from_slice(&buf[..NONCE_LEN]);

            // split the remainder into ciphertext and trailing tag
            let (msg, tag_bytes) = buf[NONCE_LEN..n].split_at_mut(n - NONCE_LEN - TAG_LEN);
            let tag = Tag::try_from(&*tag_bytes).unwrap();

            // decrypt in place; on tag-verification failure, drop the packet
            match cipher_in.decrypt_inout_detached(&nonce, b"", msg.into(), &tag) {
                Ok(()) => dev.send(msg).await.unwrap(),
                Err(_) => {
                    println!("invalid payload");
                    continue;
                },
            };
        }
    })
    .await?;

  Ok(())
}
