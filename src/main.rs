use tun_tap::{Iface, Mode};
use std::io;

fn main() -> io::Result<()>  {
    let nic = Iface::new("tun0", Mode::Tun)?;

    let mut buf = [0u8; 1504];

    loop {
        let nbytes = nic.recv(&mut buf[..])?;

        let flags = u16::from_be_bytes([buf[0], buf[1]]);
        let proto = u16::from_be_bytes([buf[2], buf[3]]);

        // if no ipv4 packet
        if proto != 0x0800 {
            continue
        }

        eprintln!(
            "read {} bytes (flags: {:x}, proto: {:x}): {:x?}", 
            nbytes - 4,
            flags,
            proto, 
            &buf[..nbytes]
        );
    }

    Ok(())
}