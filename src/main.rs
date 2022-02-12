use tun_tap::{Iface, Mode};
use std::io;

fn main() -> io::Result<()>  {
    let nic = Iface::new("tun0", Mode::Tun)?;

    let mut buf = [0u8; 1504];

    loop {
        let nbytes = nic.recv(&mut buf[..])?;

        eprintln!("read {} bytes: {:x?}", nbytes, &buf[..nbytes]);
    }

    Ok(())
}