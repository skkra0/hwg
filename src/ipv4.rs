use std::{fmt::Display, net::Ipv4Addr};

pub const ICMP: u8 = 1;
pub const TCP: u8 = 6;
pub const UDP: u8 = 17;

pub fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for chunk in header.chunks(2) {
        sum += u16::from_be_bytes([chunk[0], *chunk.get(1).unwrap_or(&0)]) as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !sum as u16
}

pub struct Ipv4Header<'a> {
    pub version_ihl: u8,
    pub dscp_ecn: u8,
    pub len: u16,
    pub id: u16,
    pub flags_foffset: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub checksum: u16,
    pub src_addr: u32,
    pub dst_addr: u32,
    opts: &'a [u8],
}

impl<'a> Ipv4Header<'a> {
    pub fn version(&self) -> u8 {
        self.version_ihl >> 4
    }

    pub fn ihl(&self) -> u8 {
        self.version_ihl & 0x0f
    }

    pub fn header_len(&self) -> usize {
        (self.version_ihl & 0x0f) as usize * 4
    }

    pub fn dscp(&self) -> u8 {
        self.dscp_ecn >> 2
    }

    pub fn ecn(&self) -> u8 {
        self.dscp_ecn & 0x3
    }

    fn flags(&self) -> u8 {
        (self.flags_foffset >> 13) as u8
    }

    pub fn df(&self) -> bool {
        self.flags() & 0x2 != 0
    }

    pub fn mf(&self) -> bool {
        self.flags() & 0x1 != 0
    }

    pub fn foffset(&self) -> u16 {
        self.flags_foffset & 0x1fff
    }

    pub fn new(protocol: u8, ttl: u8, src_addr: u32, dst_addr: u32, payload_len: u16) -> Ipv4Header<'static> {
        Ipv4Header {
            version_ihl: 0x45, // version 4, ihl 5 (no options)
            dscp_ecn: 0,
            len: 20 + payload_len,
            id: 0,
            flags_foffset: 0,
            ttl,
            protocol,
            checksum: 0, // filled in by write_to
            src_addr,
            dst_addr,
            opts: &[],
        }
    }

    pub fn write_to(&self, buf: &mut [u8]) -> Result<usize, Ipv4ParseError> {
        if self.header_len() > buf.len() {
            return Err(Ipv4ParseError::BufferTooShort)
        }
        let header_len = self.header_len();
        buf[0] = self.version_ihl;
        buf[1] = self.dscp_ecn;
        buf[2..4].copy_from_slice(&self.len.to_be_bytes());
        buf[4..6].copy_from_slice(&self.id.to_be_bytes());
        buf[6..8].copy_from_slice(&self.flags_foffset.to_be_bytes());
        buf[8] = self.ttl;
        buf[9] = self.protocol;
        buf[10] = 0;
        buf[11] = 0; // checksum placeholder
        buf[12..16].copy_from_slice(&self.src_addr.to_be_bytes());
        buf[16..20].copy_from_slice(&self.dst_addr.to_be_bytes());
        buf[20..header_len].copy_from_slice(self.opts);

        let checksum = ipv4_checksum(&buf[..header_len]);
        buf[10..12].copy_from_slice(&checksum.to_be_bytes());

        Ok(header_len)
    }
}

#[derive(Debug)]
pub enum Ipv4ParseError {
    BufferTooShort,
    InvalidVersion(u8),
    InvalidIhl(u8),
    InvalidLength(u16),
    InvalidFlags(u8),
    InvalidChecksum,
}

impl Display for Ipv4ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Ipv4ParseError::BufferTooShort => {
                write!(f, "ipv4: buffer too short: must be at least 20 bytes")?;
            },
            Ipv4ParseError::InvalidVersion(version) => {
                write!(f, "ipv4: invalid version {}: expected 4", version)?;
            },
            Ipv4ParseError::InvalidIhl(ihl) => {
                write!(f, "ipv4: invalid ihl {}: should be at least 5", ihl)?;
            },
            Ipv4ParseError::InvalidLength(len) => {
                write!(f, "ipv4: invalid length {}", len)?;
            },
            Ipv4ParseError::InvalidFlags(flags) => {
                write!(f, "ipv4: invalid flags {:#04x}", flags)?;
            },
            Ipv4ParseError::InvalidChecksum => {
                write!(f, "ipv4: invalid checksum")?;
            }
        }

        Ok(())
    }
}

pub fn has_valid_ipv4_checksum(header: &[u8]) -> bool {
    ipv4_checksum(header) == 0
}

impl<'a> TryFrom<&'a [u8]> for Ipv4Header<'a> {
    type Error = Ipv4ParseError;

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        if value.len() < 20 {
            return Err(Ipv4ParseError::BufferTooShort);
        }

        let version_ihl = value[0];

        let version = version_ihl >> 4;
        if version != 4 {
            return Err(Ipv4ParseError::InvalidVersion(version));
        }

        let ihl = (version_ihl & 0x0f) as usize;
        if ihl < 5 {
            return Err(Ipv4ParseError::InvalidIhl(ihl as u8));
        }

        let header_len = ihl * 4;
        if value.len() < header_len {
            return Err(Ipv4ParseError::BufferTooShort);
        }

        let len = u16::from_be_bytes([value[2], value[3]]);
        if (len as usize) < header_len {
            return Err(Ipv4ParseError::InvalidLength(len));
        }

        let flags_foffset = u16::from_be_bytes([value[6], value[7]]);
        let flags = (flags_foffset >> 13) as u8;
        let foffset = flags_foffset & 0x1fff;
        let df = flags & 0x2 != 0;
        let mf = flags & 0x1 != 0;
        // Reserved bit must be 0; DF and MF cannot both be set; DF requires offset 0.
        if flags & 0x4 != 0 || (df && mf) || (df && foffset != 0) {
            return Err(Ipv4ParseError::InvalidFlags(flags));
        }

        if !has_valid_ipv4_checksum(&value[..header_len]) {
            return Err(Ipv4ParseError::InvalidChecksum);
        }

        Ok(Ipv4Header {
            version_ihl,
            dscp_ecn: value[1],
            len,
            id: u16::from_be_bytes([value[4], value[5]]),
            flags_foffset,
            ttl: value[8],
            protocol: value[9],
            checksum: u16::from_be_bytes([value[10], value[11]]),
            src_addr: u32::from_be_bytes([value[12], value[13], value[14], value[15]]),
            dst_addr: u32::from_be_bytes([value[16], value[17], value[18], value[19]]),
            opts: &value[20..header_len],
        })
    }
}

impl<'a> Display for Ipv4Header<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DSCP: {}\n", self.dscp())?;
        write!(f, "ECN: {}\n", self.ecn())?;
        write!(f, "Length: {}\n", self.len)?;
        write!(f, "ID: {}\n", self.id)?;
        write!(f, "DF: {}\n", self.df())?;
        write!(f, "MF: {}\n", self.mf())?;
        write!(f, "Offset: {}\n", self.foffset())?;
        write!(f, "TTL: {}\n", self.ttl)?;
        write!(f, "Protocol: {}\n", match self.protocol {
            ICMP => "ICMP",
            TCP => "TCP",
            UDP => "UDP",
            _ => stringify!(self.protocol),
        })?;
        write!(f, "src: {}\n", Ipv4Addr::from_bits(self.src_addr))?;
        write!(f, "dst: {}", Ipv4Addr::from_bits(self.dst_addr))?;

        Ok(())
    }
}