use std::{env, net::{IpAddr, Ipv4Addr, SocketAddr}, str::FromStr, sync::Arc};

use anyhow::Result;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce, aead::{Generate}};
use tokio::net::{UdpSocket};
use tun_rs::DeviceBuilder;

use crypto::{NONCE_LEN, TAG_LEN};

mod crypto;
mod ipv4;

const MAX_IP_LEN: usize = 65535;
#[tokio::main]
async fn main() -> Result<()> {
    let self_addr = match env::var("SELF_ADDR") {
        Ok(addr) => Ipv4Addr::from_str(addr.as_str()).expect("Invalid SELF_ADDR"),
        Err(_) => Ipv4Addr::new(10, 0, 0, 1)
    };

    let peer_addr = match env::var("PEER_ADDR") {
        Ok(addr) => {
            let ip = Ipv4Addr::from_str(addr.as_str()).expect("Invalid PEER_ADDR");
            SocketAddr::new(IpAddr::V4(ip), 51820)
        },
        Err(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 100, 1)), 51820)
    };
    println!("{} {}", self_addr, peer_addr);

    let dev = DeviceBuilder::new()
        .name("utun7")
        .ipv4(self_addr, 24, None)
        .mtu(1420)
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
        // layout: [plaintext/ciphertext | nonce | tag]
        let mut buf = [0u8; MAX_IP_LEN + NONCE_LEN + TAG_LEN];
        loop {
            // read the IP packet in place
            let n = dev_out.recv(&mut buf).await.unwrap();
            let ip_header = match ipv4::Ipv4Header::try_from(&buf[..NONCE_LEN+TAG_LEN]) {
                Ok(h) => h,
                Err(e) =>{
                    eprintln!("{}", e);
                    continue;
                }
            };
            println!("{}", ip_header);

            // fresh random nonce every packet — never reused with this key
            let nonce = Nonce::generate();
            match crypto::encrypt(&mut buf[..n+NONCE_LEN+TAG_LEN], &cipher_out, nonce) {
                Ok(buf) => {
                    sock_out
                        .send_to(buf, peer_addr)
                        .await
                        .unwrap();
                    println!("sent");
                },
                Err(e) => {
                    eprintln!("{}", e);
                    continue;
                }
            };
        }
    });

    // inbound: UDP → TUN
    let cipher_in = cipher;
    tokio::spawn(async move {
        // layout: [ciphertext | nonce | tag]
        let mut buf = [0u8; MAX_IP_LEN + crypto::NONCE_LEN + crypto::TAG_LEN];
        loop {
            let (n, _from) = sock.recv_from(&mut buf).await.unwrap();

            // drop anything too short to contain a nonce + tag
            if n < crypto::NONCE_LEN + crypto::TAG_LEN {
                continue;
            }

            match crypto::decrypt(&mut buf[..n], &cipher_in) {
                Ok((msg, _)) => {
                    dev.send(msg).await.unwrap();
                    println!("decrypted and sent");
                }
                Err(e) => {
                    eprintln!("invalid payload: {}", e);
                    continue;
                }
            };
        }
    })
    .await?;

  Ok(())
}

