use std::collections::HashMap;
use std::hash::Hash;
use std::io;
use std::net::Ipv4Addr;
use tun_tap::{Iface, Mode};

mod tcp;

fn main() -> io::Result<()> {
    loop {
        let nbytes = nic.recv(&mut buf[..])?;

        // if s/without_packet_info/new/:
        //
        // let _eth_flags = u16::from_be_bytes([buf[0], buf[1]]);
        // let eth_proto = u16::from_be_bytes([buf[2], buf[3]]);

        // // if not ipv4 packet
        // if eth_proto != 0x0800 {
        //     continue;
        // }
        // and also include on send

        // parsing ipv4 header
        match etherparse::Ipv4HeaderSlice::from_slice(&buf[..nbytes]) {
            Ok(ip_header) => {
                let src = ip_header.source_addr();
                let dst = ip_header.destination_addr();

                // if not tcp packet
                if ip_header.protocol() != 0x06 {
                    continue;
                }

                // parsing tcp header
                match etherparse::TcpHeaderSlice::from_slice(&buf[ip_header.slice().len()..nbytes])
                {
                    Ok(tcp_header) => {
                        use std::collections::hash_map::Entry;

                        let datai = ip_header.slice().len() + tcp_header.slice().len();

                        match connections.entry(Quad {
                            src: (src, tcp_header.source_port()),
                            dst: (dst, tcp_header.destination_port()),
                        }) {
                            Entry::Occupied(mut c) => {
                                c.get_mut().on_packet(
                                    &mut nic,
                                    ip_header,
                                    tcp_header,
                                    &buf[datai..nbytes],
                                )?;
                            }
                            Entry::Vacant(e) => {
                                if let Some(c) = tcp::Connection::accept(
                                    &mut nic,
                                    ip_header,
                                    tcp_header,
                                    &buf[datai..nbytes],
                                )? {
                                    e.insert(c);
                                }
                            }
                        }
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
