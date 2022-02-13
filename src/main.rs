use tun_tap::{Iface, Mode};
use std::io;
use std::fs;
use std::{thread, time::Duration};

fn main() -> io::Result<()>  {
    let nic = Iface::new("tun0", Mode::Tun)?;
    //fs::write("/sys/class/leds/red_red/trigger", "heartbeat").expect("error");

    let mut buf = [0u8; 1504];

    loop {
        let nbytes = nic.recv(&mut buf[..])?;

        let _eth_flags = u16::from_be_bytes([buf[0], buf[1]]);
        let eth_proto = u16::from_be_bytes([buf[2], buf[3]]);

        // if not ipv4 packet
        if eth_proto != 0x0800 {
            continue;
        }

        // parsing ipv4 header
        match etherparse::Ipv4HeaderSlice::from_slice(&buf[4..nbytes]) {
            Ok(p) => {
                let src = p.source_addr();
                let dst = p.destination_addr();
                let proto = p.protocol();

                // if not tcp packet
                if proto != 0x06 {
                    continue;
                }
                
                // parsing tcp header
                match etherparse::TcpHeaderSlice::from_slice(&buf[4 + p.slice().len()..]) {
                    Ok(p) => {
                        // (srcip, srcport, dstip, dstport) = 
                        eprintln!(
                            "{} → {} {}b of tcp to port {}", 
                            src, 
                            dst, 
                            p.slice().len(),
                            p.destination_port()
                        );
                    },
                    Err(e) => {
                        eprintln!("ignoring weird tcp packet {:?}", e);
                    }
                }
            },
            Err(e) => {
                eprintln!("ignoring weird ip packet {:?}", e);
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