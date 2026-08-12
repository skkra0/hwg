use std::{collections::HashMap, fs::File, io::{self, BufRead}, net::{Ipv4Addr, SocketAddr, SocketAddrV4}, str::FromStr};
use anyhow::{Result, anyhow};
use base64::{Engine as _, engine::general_purpose::STANDARD};

#[derive(Debug, Clone, Copy)]
pub struct Interface {
    pub addr: Ipv4Addr,
    pub listen_port: u16,
    pub priv_key: [u8; 32],
}

#[derive(Debug, Clone, Copy)]
pub struct Peer {
    pub pub_key: [u8;32],
    pub addr: Ipv4Addr,
    pub endpoint: Option<SocketAddr>,
}
#[derive(Debug, Clone)]
pub struct Config {
    pub interface: Interface,
    pub peers: HashMap<[u8;32], Peer>,
}

fn split_key_value(line: &str) -> Result<(&str, &str)> {
    let (key, value) = line.split_once("=").ok_or(anyhow!("Invalid line {line}"))?;
    Ok((key.trim(), value.trim()))
}

fn parse_key(value: &str) -> Result<[u8;32]> {
    let bytes = STANDARD.decode(value)?;
    let key: [u8; 32] = bytes
        .try_into()
        .map_err(|v: Vec<u8>| anyhow!("private key is {} bytes, expected 32", v.len()))?;

    Ok(key)
}

fn parse_interface(bufreader: &mut impl BufRead, buf: &mut String) -> Result<(Interface, bool)> {
    let mut addr: Option<Ipv4Addr> = None;
    let mut listen_port: Option<u16> = None;
    let mut priv_key: Option<[u8; 32]> = None;
    let mut reparse_line = false;
    loop {
        buf.clear();
        let size = bufreader.read_line(buf)?;
        if size == 0 {
            break;
        } 

        let line = buf.trim();
        if line.is_empty() || line.starts_with("#") {
            continue;
        } 

        let (key, value) = match split_key_value(line) {
            Err(_) => {
                reparse_line = true;
                break;
            },
            Ok((key, value)) => (key, value),
        };

        match key {
            "Address" => {
                if addr.is_some() {
                    return Err(anyhow!("interface: duplicate interface address"))
                }
                addr = Some(Ipv4Addr::from_str(value)?);
            },
            "ListenPort" => {
                if listen_port.is_some() {
                    return Err(anyhow!("interface: duplicate listen port"));
                }
                listen_port = Some(u16::from_str(value)?);
            },
            "PrivateKey" => {
                if priv_key.is_some() {
                    return Err(anyhow!("interface: duplicate private key"));
                }
                priv_key = Some(parse_key(value)?);
            },
            _ => {
                eprintln!("interface: ignoring unknown field {key}");
            }
        };
    };

    let addr = addr.ok_or(anyhow!("interface: missing interface address"))?;
    let listen_port = match listen_port {
        Some(l) => l,
        None => 0,
    };
    let priv_key = priv_key.ok_or(anyhow!("interface: missing private key"))?;

    Ok((Interface {
        addr,
        listen_port,
        priv_key,
    }, reparse_line))
}

fn parse_peer(bufreader: &mut impl BufRead, buf: &mut String) -> Result<(Peer, bool)> {
    let mut pub_key: Option<[u8;32]> = None;
    let mut allowed_ip: Option<Ipv4Addr> = None;
    let mut endpoint: Option<SocketAddr> = None;
    let mut reparse_line = false;
    loop {
        buf.clear();
        if bufreader.read_line(buf)? == 0 {
            break;
        }

        let line = buf.trim();
        if line.is_empty() || line.starts_with("#") {
            continue;
        }

        let (key, value) = match split_key_value(line) {
            Err(_) => {
                reparse_line = true;
                break;
            },
            Ok((key, value)) => (key, value),
        };

        match key {
            "PublicKey" => {
                if pub_key.is_some() {
                    return Err(anyhow!("peer: duplicate public key"));
                }
                pub_key = Some(parse_key(value)?);
            },
            "AllowedIPs" => {
                if allowed_ip.is_some() {
                    return Err(anyhow!("peer: duplicate allowed ips"));
                }

                allowed_ip = Some(Ipv4Addr::from_str(value)?);
            },
            "Endpoint" => {
                if endpoint.is_some() {
                    return Err(anyhow!("peer: duplicate endpoint"));
                }
                endpoint = Some(SocketAddrV4::from_str(value)?.into());
            }
            _ => {
                eprintln!("peer: ignoring unknown field {key}");
            }
        }
    };

    let pub_key = pub_key.ok_or(anyhow!("missing public key"))?;
    let allowed_ip = allowed_ip.ok_or(anyhow!("missing allowed ips"))?;

    Ok((Peer {
        pub_key,
        addr: allowed_ip,
        endpoint,
    }, reparse_line))
}

fn read_from_reader(mut bufreader: impl BufRead) -> Result<Config> {
    let mut interface: Option<Interface> = None;
    let mut peers = HashMap::new();
    let mut buf = String::new();
    let mut reparse_line = false;
    loop {
        let block: &str;
        if reparse_line {
            reparse_line = false;
        } else { 
            buf.clear();
            let size = bufreader.read_line(&mut buf)?;
            if size == 0 {
                break;
            }
        }

        block = buf.trim();
            if block.is_empty() || block.starts_with("#") {
                continue;
        }

        match block {
            "[Interface]" => {
                if interface.is_some() {
                    return Err(anyhow!("duplicate [Interface] block"));
                }
                let (intf, reparse) = parse_interface(&mut bufreader, &mut buf)?;
                interface = Some(intf);
                reparse_line = reparse;
            },
            "[Peer]" => {
                let (peer, reparse) = parse_peer(&mut bufreader, &mut buf)?;
                peers.insert(peer.pub_key, peer);
                reparse_line = reparse;
            },
            block => {
                return Err(anyhow!("unexpected text {block}"));
            }
        };
    };
    let interface = interface.ok_or_else(|| anyhow!("missing [Interface] block"))?;
    Ok(Config {
        interface,
        peers,
    })
}

pub fn read_from_file(fname: &str) -> Result<Config> {
    let file: File = File::open(fname)?;
    read_from_reader(io::BufReader::new(file))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    fn parse(s: &str) -> Result<Config> {
        read_from_reader(Cursor::new(s.as_bytes()))
    }

    #[test]
    fn missing_interface() {
        let err = parse("").unwrap_err();
        assert!(err.to_string().contains("missing [Interface]"))
    }

    #[test]
    fn skips_blank_and_comment() {
        let cfg = parse("
# comment
[Interface]
Address = 10.0.0.1
ListenPort = 51820
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
").unwrap();
        let interface = cfg.interface;
        assert!(interface.addr.eq(&Ipv4Addr::new(10, 0, 0, 1)));
        assert!(interface.listen_port.eq(&51820));
        assert!(interface.priv_key.eq(&parse_key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap()));
    }

    #[test]
    fn ignores_unknown_options() {
        let cfg = parse("[Interface]
Address = 10.0.0.1
ListenPort = 51820
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
UnknownField1 = asdf
UnknownField2 = UnknownValue2
").unwrap();
        let interface = cfg.interface;
        assert!(interface.addr.eq(&Ipv4Addr::new(10, 0, 0, 1)));
        assert!(interface.listen_port.eq(&51820));
        assert!(interface.priv_key.eq(&parse_key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap()));
    }

    #[test]
    fn parses_peers() {
        let cfg = parse("[Peer]
PublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
AllowedIPs = 10.10.1.3
[Interface]
Address = 10.0.0.1
ListenPort = 51820
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
[Peer]
PublicKey = ABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
AllowedIPs = 10.10.1.4
Endpoint = 172.16.0.1:51820
").unwrap();
        let key1 = parse_key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap();
        let key2 = parse_key("ABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap();
        let peer1 = cfg.peers[&key1];
        let peer2 = cfg.peers[&key2];
        assert!(peer1.addr.eq(&Ipv4Addr::new(10,10,1,3)));
        assert!(peer1.endpoint.is_none());
        assert!(peer2.addr.eq(&Ipv4Addr::new(10,10,1,4)));
        assert!(peer2.endpoint.unwrap().eq(&SocketAddrV4::from_str("172.16.0.1:51820").unwrap().into()))
    }
}