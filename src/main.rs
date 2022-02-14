use std::collections::HashMap;
use std::hash::Hash;
use std::io;
use std::net::Ipv4Addr;
use tun_tap::{Iface, Mode};

mod tcp;

#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
struct Quad {
    src: (Ipv4Addr, u16),
    dst: (Ipv4Addr, u16),
}

fn main() -> io::Result<()> {
    let mut connections: HashMap<Quad, tcp::State> = Default::default();

    let mut nic = Iface::new("tun0", Mode::Tun)?;
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
            Ok(ip_header) => {
                let src = ip_header.source_addr();
                let dst = ip_header.destination_addr();

                // if not tcp packet
                if ip_header.protocol() != 0x06 {
                    continue;
                }

                // parsing tcp header
                match etherparse::TcpHeaderSlice::from_slice(
                    &buf[4 + ip_header.slice().len()..nbytes],
                ) {
                    Ok(tcp_header) => {
                        let datai = 4 + ip_header.slice().len() + tcp_header.slice().len();

                        connections
                            .entry(Quad {
                                src: (src, tcp_header.source_port()),
                                dst: (dst, tcp_header.destination_port()),
                            })
                            .or_default()
                            .on_packet(&mut nic, ip_header, tcp_header, &buf[datai..nbytes])?;
                    }
                    Err(e) => {
                        eprintln!("ignoring weird tcp packet {:?}", e);
                    }
                }
            }
            Err(e) => {
                eprintln!("ignoring weird ip packet {:?}", e);
            }
        }
    }
}
