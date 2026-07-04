use tun_rs::DeviceBuilder;

use crate::{ipv4::Ipv4Header, ping::PingRequest};

mod ipv4;
mod ping;

fn main() -> Result<(), String> {
  let dev = DeviceBuilder::new()
    .name("utun7")
    .ipv4("10.0.0.12", 24, None)
    .mtu(1400)
    .build_sync()
    .unwrap();

  let mut buf = [0; 65535];
  let mut out = [0; 65535];
  loop {
      let len = dev.recv(&mut buf).unwrap();
      let header = match Ipv4Header::try_from(&buf[..len]) {
        Ok(h) => h,
        Err(e) => { eprintln!("Error parsing ipv4 header: {e}"); continue; }
      };

      println!("{}", header);
      if header.protocol == ipv4::ICMP {
        let pr = match PingRequest::try_from(&buf[header.header_len()..len]) {
          Ok(pr) => {
            println!("{}", pr);
            pr
          },
          Err(e) => {
            eprintln!("{}", e);
            continue;
          }
        };

        let len = match ping::build_reply(&pr, &header, &mut out) {
          Ok(len) => len,
          Err(e) => { eprintln!("{}", e); continue; }
        };

        dev.send(&out[..len]).unwrap();
        println!("sent {} bytes", len);
      }

      print!("\n\n");
  }
}
