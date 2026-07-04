use std::fmt::Display;

use crate::ipv4;
pub struct PingRequest<'a> {
    pub id: u16,
    pub seq: u16,
    pub payload: &'a [u8],
}

impl<'a> PingRequest<'a> {
    pub fn encoded_len(&self) -> usize {
        8 + self.payload.len()
    }

    pub fn write_reply_to(&self, buf: &mut [u8]) -> Result<usize, PingError> {
        if self.encoded_len() > buf.len() {
            return Err(PingError::BufferTooShort)
        }

        buf[0] = 0;
        buf[1] = 0;
        buf[2..4].copy_from_slice(&[0, 0]); // zero the checksum field before computing the checksum below
        buf[4..6].copy_from_slice(&self.id.to_be_bytes());
        buf[6..8].copy_from_slice(&self.seq.to_be_bytes());
        buf[8..self.encoded_len()].copy_from_slice(self.payload);

        let checksum= ipv4::ipv4_checksum(&buf[..self.encoded_len()]);
        buf[2..4].copy_from_slice(&checksum.to_be_bytes());

        Ok(self.encoded_len())
    }
}

/// Builds an ICMP echo reply (with its IPv4 header) into `out`, returning the total length written.
pub fn build_reply(pr: &PingRequest, header: &ipv4::Ipv4Header, out: &mut [u8]) -> Result<usize, String> {
  let reply_header = ipv4::Ipv4Header::new(ipv4::ICMP, 64, header.dst_addr, header.src_addr, pr.encoded_len() as u16);
  let hlen = reply_header.write_to(out).map_err(|e| format!("couldn't build ipv4 header: {}", e))?;
  pr.write_reply_to(&mut out[hlen..]).map_err(|e| format!("couldn't build ping reply: {}", e))?;
  Ok(reply_header.len as usize)
}

impl<'a> Display for PingRequest<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ping: id={}, seq={}", self.id, self.seq)?;
        Ok(())
    }
}

impl<'a> TryFrom<&'a [u8]> for PingRequest<'a> {
    type Error = PingError;

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        if value.len() < 8 {
            return Err(PingError::BufferTooShort);
        }

        if !ipv4::has_valid_ipv4_checksum(&value) {
            return Err(PingError::InvalidChecksum);
        }


        let icmp_type = value[0];
        let code = value[1];

        if icmp_type != 8 || code != 0 {
            return Err(PingError::InvalidMessage(icmp_type, code))
        }

        Ok(PingRequest {
            id: u16::from_be_bytes([value[4], value[5]]),
            seq: u16::from_be_bytes([value[6], value[7]]),
            payload: &value[8..]
        })
    }
}

pub enum PingError {
    BufferTooShort,
    InvalidChecksum,
    InvalidMessage(u8, u8),
}

impl Display for PingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PingError::BufferTooShort => write!(f, "buffer too short"),
            PingError::InvalidChecksum => write!(f, "invalid checksum"),
            PingError::InvalidMessage(icmp_type, code) => {
                write!(f, "unexpected icmp type {}, code {}", icmp_type, code)
            },
        }
    }
}