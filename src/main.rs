use tun_tap::{Iface, Mode};
use std::io;

fn main() -> io::Result<()>  {
    let nic = Iface::new("tun0", Mode::Tun)?;

    let mut buf = [0u8; 1504];

    loop {
        let nbytes = nic.recv(&mut buf[..])?;

        let _eth_flags = u16::from_be_bytes([buf[0], buf[1]]);
        let eth_proto = u16::from_be_bytes([buf[2], buf[3]]);

        // if no ipv4 packet
        if eth_proto != 0x0800 {
            continue
        }

        match etherparse::Ipv4HeaderSlice::from_slice(&buf[4..nbytes]) {
            Ok(p) => {
                let src = p.source_addr();
                let dst = p.destination_addr();
                let proto = p.protocol();

                eprintln!("{} → {} {}b of protocol {}", src, dst, proto, p.payload_len());
            },
            Err(e) => {
                eprintln!("ignoring weird packet {:?}", e);
            }
        }

        // eprintln!(
        //     "read {} bytes (flags: {:x}, proto: {:x}): {:x?}", 
        //     nbytes - 4,
        //     flags,
        //     proto, 
        //     &buf[..nbytes]
        // );
    }
}