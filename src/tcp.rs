use std::io;

pub enum State {
    //Listen,
    SybnRcvd,
    Estab,
}

pub struct Connection {
    state: State,
    send: SendSequenceSpace,
    recv: RecvSequenceSpace,
    ip: etherparse::Ipv4Header,
}

struct SendSequenceSpace {
    /// send unacknowledged
    una: u32,
    /// send next
    nxt: u32,
    /// send window
    wnd: u16,
    /// send urgent pointer
    up: bool,
    /// segment sequence number used for last window update
    wl1: usize,
    /// segment acknowledgment number used for last window update
    wl2: usize,
    /// initial send sequence number
    iss: u32,
}

struct RecvSequenceSpace {
    /// receive next
    nxt: u32,
    /// receive window
    wnd: u16,
    /// receive urgent pointer
    up: bool,
    /// initial receive sequence number
    irs: u32,
}

// impl Default for Connection {
//     fn default() -> Self {
//         // State::Closed
//         Connection {
//             state: State::Listen,
//         }
//     }
// }

impl Connection {
    pub fn accept<'a>(
        nic: &mut tun_tap::Iface,
        ip_header: etherparse::Ipv4HeaderSlice<'a>,
        tcp_header: etherparse::TcpHeaderSlice<'a>,
        data: &'a [u8],
    ) -> io::Result<Option<Self>> {
        let mut buf = [0u8; 1500];

        if !tcp_header.syn() {
            // only expected SYN packet
            return Ok(None);
        }

        let iss = 0;

        let mut c = Connection {
            state: State::SybnRcvd,
            send: SendSequenceSpace {
                iss,
                una: iss,
                nxt: iss + 1,
                wnd: 10,
                up: false,

                wl1: 0,
                wl2: 0,
            },
            recv: RecvSequenceSpace {
                irs: tcp_header.sequence_number(),
                nxt: tcp_header.sequence_number() + 1,
                wnd: tcp_header.window_size(),
                up: false,
            },
            ip: etherparse::Ipv4Header::new(
                0,
                64,
                etherparse::IpTrafficClass::Tcp,
                [
                    ip_header.destination()[0],
                    ip_header.destination()[1],
                    ip_header.destination()[2],
                    ip_header.destination()[3],
                ],
                [
                    ip_header.source()[0],
                    ip_header.source()[1],
                    ip_header.source()[2],
                    ip_header.source()[3],
                ],
            ),
        };

        // need to start establishing a connection
        let mut syn_ack = etherparse::TcpHeader::new(
            tcp_header.destination_port(),
            tcp_header.source_port(),
            c.send.iss,
            c.send.wnd,
        );

        syn_ack.acknowledgment_number = c.recv.nxt;
        syn_ack.syn = true;
        syn_ack.ack = true;

        c.ip.set_payload_len(syn_ack.header_len() as usize + 0);

        // the kernel does this for us
        // syn_ack.checksum = syn_ack
        //     .calc_checksum_ipv4(&c.ip, &[])
        //     .expect("filed to compute ckecksum");

        // eprintln!("got ip header:\n{:02x?}", ip_header);
        // eprintln!("got tcp header:\n{:02x?}", tcp_header);

        // write out the headers
        let unwritten = {
            let mut unwritten = &mut buf[..];
            c.ip.write(&mut unwritten);
            syn_ack.write(&mut unwritten);
            unwritten.len()
        };

        //eprintln!("responding with {:02x?}", &buf[..buf.len() - unwritten]);

        nic.send(&buf[..unwritten]);

        Ok(Some(c))

        // eprintln!(
        //     "{}:{} → {}:{} {}b of tcp",
        //     ip_header.source_addr(),
        //     tcp_header.source_port(),
        //     ip_header.destination_addr(),
        //     tcp_header.destination_port(),
        //     data.len()
        // );
    }

    pub fn on_packet<'a>(
        &mut self,
        nic: &mut tun_tap::Iface,
        ip_header: etherparse::Ipv4HeaderSlice<'a>,
        tcp_header: etherparse::TcpHeaderSlice<'a>,
        data: &'a [u8],
    ) -> io::Result<()> {
        // acceptable ack check
        // SND.UNA < SEG.ACK =< SND.NXT
        // but remember wrapping!
        let ackn = tcp_header.acknowledgment_number();

        if self.send.una < ackn {
            // check is violated iff n is between u and a
            if self.send.nxt >= self.send.una && self.send.nxt < ackn {
                return Ok(());
            }
        } else {
            // check is okay iff n is between u and a
            if self.send.nxt >= ackn && self.send.nxt < self.send.una {

            } else {
                return Ok(());
            }
        }

        // valid segment ckeck 
        

        match self.state {
            // State::Listen => todo!(),
            State::SybnRcvd => {
                // expect to get an ACK for our SYN
            }
            State::Estab => {
                unimplemented!()
            }
        }

        Ok(())
    }
}
