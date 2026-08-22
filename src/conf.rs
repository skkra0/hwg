use std::{fmt::Debug, collections::HashMap, fs::File, io::{self, BufRead}, net::{Ipv4Addr, SocketAddr, SocketAddrV4}, str::FromStr};
use anyhow::{Result, anyhow};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ip_network::Ipv4Network;
use ip_network_table::IpNetworkTable;

#[derive(Debug, Clone, Copy)]
pub struct Interface {
    pub addr: Ipv4Addr,
    pub listen_port: u16,
    pub priv_key: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct Peer {
    pub pub_key: [u8;32],
    pub allowed_ips: Vec<Ipv4Network>,
    pub endpoint: Option<SocketAddr>,
}

pub struct Config {
    pub interface: Interface,
    pub peers: HashMap<[u8;32], Peer>,
    pub network_table: IpNetworkTable<[u8; 32]>,
}

impl Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config").field("interface", &self.interface).field("peers", &self.peers).finish()
    }
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
                    return Err(anyhow!("parse error (interface): duplicate interface address"))
                }
                addr = Some(Ipv4Addr::from_str(value)?);
            },
            "ListenPort" => {
                if listen_port.is_some() {
                    return Err(anyhow!("parse error (interface): duplicate listen port"));
                }
                listen_port = Some(u16::from_str(value)?);
            },
            "PrivateKey" => {
                if priv_key.is_some() {
                    return Err(anyhow!("parse error (interface): duplicate private key"));
                }
                priv_key = Some(parse_key(value)?);
            },
            _ => {
                eprintln!("parse error (interface): ignoring unknown field {key}");
            }
        };
    };

    let addr = addr.ok_or(anyhow!("parse error (interface): missing interface address"))?;
    let listen_port = match listen_port {
        Some(l) => l,
        None => 0,
    };
    let priv_key = priv_key.ok_or(anyhow!("parse error (interface): missing private key"))?;

    Ok((Interface {
        addr,
        listen_port,
        priv_key,
    }, reparse_line))
}

fn parse_peer(bufreader: &mut impl BufRead, buf: &mut String) -> Result<(Peer, bool)> {
    let mut pub_key: Option<[u8;32]> = None;
    let mut allowed_ips: Option<Vec<Ipv4Network>> = None;
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
                    return Err(anyhow!("parse error (peer): duplicate public key"));
                }
                pub_key = Some(parse_key(value)?);
            },
            "AllowedIPs" => {
                if allowed_ips.is_some() {
                    return Err(anyhow!("parse error (peer): duplicate allowed ips"));
                }

                let mut ip_list = Vec::new();
                
                for val in value.split(",") {
                    let ipv4net = Ipv4Network::from_str(val.trim())?;
                    ip_list.push(ipv4net);
                }

                allowed_ips = Some(ip_list);
            },
            "Endpoint" => {
                if endpoint.is_some() {
                    return Err(anyhow!("parse error (peer): duplicate endpoint"));
                }
                endpoint = Some(SocketAddrV4::from_str(value)?.into());
            }
            _ => {
                eprintln!("peer: ignoring unknown field {key}");
            }
        }
    };

    let pub_key = pub_key.ok_or(anyhow!("parse error (peer): missing public key"))?;
    let allowed_ips = allowed_ips.ok_or(anyhow!("parse error (peer): missing allowed ips"))?;

    Ok((Peer {
        pub_key,
        allowed_ips,
        endpoint,
    }, reparse_line))
}

fn read_from_reader(mut bufreader: impl BufRead) -> Result<Config> {
    let mut interface: Option<Interface> = None;
    let mut peers = HashMap::new();
    let mut buf = String::new();
    let mut reparse_line = false;

    let mut network_table = IpNetworkTable::new();
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
                    return Err(anyhow!("parse error: duplicate [Interface] block"));
                }
                let (intf, reparse) = parse_interface(&mut bufreader, &mut buf).map_err(|e| anyhow!("parse error (interface): {e}"))?;
                interface = Some(intf);
                reparse_line = reparse;
            },
            "[Peer]" => {
                let (peer, reparse) = parse_peer(&mut bufreader, &mut buf).map_err(|e| anyhow!("parse error (peer): {e}"))?;
                for ip in &peer.allowed_ips {
                    network_table.insert(*ip, peer.pub_key.clone());
                }
                peers.insert(peer.pub_key, peer);
                reparse_line = reparse;
            },
            block => {
                return Err(anyhow!("parse error: unexpected text {block}"));
            }
        };
    };
    let interface = interface.ok_or_else(|| anyhow!("parse error: missing [Interface] block"))?;
    Ok(Config {
        interface,
        peers,
        network_table,
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
AllowedIPs = 10.192.124.0/24
[Interface]
Address = 10.0.0.1
ListenPort = 51820
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
[Peer]
PublicKey = ABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
AllowedIPs = 192.168.0.0/16
Endpoint = 172.16.0.1:51820
").unwrap();
        let key1 = parse_key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap();
        let key2 = parse_key("ABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap();
        let peer1 = &cfg.peers[&key1];
        let peer2 = &cfg.peers[&key2];
        assert!(peer1.allowed_ips.contains(&Ipv4Network::from_str("10.192.124.0/24").unwrap()));
        assert!(peer1.endpoint.is_none());
        assert!(peer2.allowed_ips.contains(&Ipv4Network::from_str("192.168.0.0/16").unwrap()));
        assert!(peer2.endpoint.unwrap().eq(&SocketAddrV4::from_str("172.16.0.1:51820").unwrap().into()))
    }
}