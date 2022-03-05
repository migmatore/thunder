use std::io;

pub enum State {
    //Listen,
    SybnRcvd,
    Estab,
}

impl State {
    fn is_synchronized(&self) -> bool {
        match *self {
            State::SybnRcvd => false,
            State::Estab => true,
        }
    }
}

pub struct Connection {
    state: State,
    send: SendSequenceSpace,
    recv: RecvSequenceSpace,
    ip: etherparse::Ipv4Header,
    tcp: etherparse::TcpHeader,
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
        let wnd = 10;

        let mut c = Connection {
            state: State::SybnRcvd,
            send: SendSequenceSpace {
                iss,
                una: iss,
                nxt: iss,
                wnd: wnd,
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
            tcp: etherparse::TcpHeader::new(
                tcp_header.destination_port(),
                tcp_header.source_port(),
                iss,
                wnd,
            ),
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

        self.tcp.syn = true;
        self.tcp.ack = true;

        c.write(nic, &[])?;

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

    fn write(&mut self, nic: &mut tun_tap::Iface, payload: &[u8]) -> io::Result<usize> {
        let mut buf = [0u8; 1500];

        self.tcp.sequence_number = self.send.nxt;
        self.tcp.acknowledgment_number = self.recv.nxt;

        let size = std::cmp::min(
            buf.len(),
            self.tcp.header_len() as usize + self.ip.header_len() as usize + payload.len(),
        );

        self.ip.set_payload_len(size);

        // the kernel does this for us
        // self.tcp.checksum = self.tcp
        //     .calc_checksum_ipv4(&self.ip, &[])
        //     .expect("filed to compute ckecksum");

        // eprintln!("got ip header:\n{:02x?}", ip_header);
        // eprintln!("got tcp header:\n{:02x?}", tcp_header);

        // write out the headers

        use std::io::Write;

        let mut unwritten = &mut buf[..];

        self.ip.write(&mut unwritten);
        self.tcp.write(&mut unwritten);
        let payload_bytes = unwritten.write(payload)?;
        let unwritten = unwritten.len();

        self.send.nxt.wrapping_add(payload_bytes as u32);

        if self.tcp.syn {
            self.send.nxt = self.send.nxt.wrapping_add(1);
            self.tcp.syn = false;
        }

        if self.tcp.fin {
            self.send.nxt = self.send.nxt.wrapping_add(1);
            self.tcp.fin = false;
        }

        //eprintln!("responding with {:02x?}", &buf[..buf.len() - unwritten]);

        nic.send(&buf[..buf.len() - unwritten])?;
        Ok(payload_bytes)
    }

    fn send_rst(&mut self, nic: &mut tun_tap::Iface) -> io::Result<()> {
        self.tcp.rst = true;
        // TODO: fix sequence numbers here
        // If the incoming segment has an ACK field, the reset takes its
        // sequence number from the ACK field of the segment, otherwise the 
        // reset has sequence number zero and the ACK field is set to the sum
        // of the sequence number and segment lenght of the incoming segment.
        // The connection remains in the same state.
        //
        // TODO: handle syncronized RST
        // If the connection is in a syncronized state (ESTABLISHED,
        // FIN_WAIT-1, FIN-WAIT-2, CLOSE-WAIT, CLOSING, LAST-ACK, TIME-WAIT),
        // any unacceptable segmnet (out of window sequence nubmer or 
        // unacceptible acknowledgment number) must elicit only an empty 
        // acknowledgment segment containing the current send-sequence number
        // and an acknowledgment indicating the next sequence number expected
        // to be received, and the connection remains in the same state
        self.tcp.sequence_number = 0;
        self.tcp.acknowledgment_number = 0;
        self.write(nic, &[])?;
        Ok(())
    }

    pub fn on_packet<'a>(
        &mut self,
        nic: &mut tun_tap::Iface,
        ip_header: etherparse::Ipv4HeaderSlice<'a>,
        tcp_header: etherparse::TcpHeaderSlice<'a>,
        data: &'a [u8],
    ) -> io::Result<()> {
        // first, check that sequence numbers are valid
        //
        // acceptable ack check
        // SND.UNA < SEG.ACK =< SND.NXT
        // but remember wrapping!
        //
        let ackn = tcp_header.acknowledgment_number();

        if !is_between_wrapped(self.send.una, ackn, self.send.nxt.wrapping_add(1)) {
            if !self.state.is_synchronized() {
                // accroding to Reset Generation< we should send a RST
                self.send_rst(nic);
            }

            return Ok(());
            // return Err(io::Error::new(
            //     io::ErrorKind::BrokenPipe,
            //     "tried to ack unset byte",
            // ));
        }

        //
        // valid segment ckeck. okay if it acks at least one byte, which means that at least one of
        // the following is true:
        //
        // RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
        // RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND
        //
        let seqn = tcp_header.sequence_number();

        let mut slen = data.len() as u32;

        if tcp_header.fin() {
            slen += 1;
        }

        if tcp_header.syn() {
            slen += 1;
        }

        let w_end = self.recv.nxt.wrapping_add(self.recv.wnd as u32);

        if slen == 0 {
            // zero-length segment has separate rules for acceptance
            if self.recv.wnd == 0 {
                if seqn != self.recv.nxt {
                    return Ok(());
                }
            } else if !is_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn, w_end) {
                return Ok(());
            }
        } else {
            if self.recv.wnd == 0 {
                return Ok(());
            } else if !is_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn, w_end)
                && !is_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn + slen - 1, w_end)
            {
                return Ok(());
            }
        }

        match self.state {
            // State::Listen => todo!(),
            State::SybnRcvd => {
                // expect to get an ACK for our SYN
                if !tcp_header.ack() {
                    return Ok(());
                }

                // must have ACKed our SYN, since we detected at least one acked byte,
                // and we have only sent one byte (THE SYN).
                self.state = State::Estab;

                // now let's terminate the connection!
            }
            State::Estab => {
                unimplemented!()
            }
        }

        Ok(())
    }
}

fn is_between_wrapped(start: u32, x: u32, end: u32) -> bool {
    use std::cmp::Ordering;

    match start.cmp(&x) {
        Ordering::Equal => return false,
        Ordering::Less => {
            // we have:
            //
            // 0 |-----------S---X---------------| (wraparound)
            //
            // X is between S and E (S < X < E) in these cases:
            //
            // 0 |-----------S---X--E------------| (wraparound)
            //
            // 0 |--------E--S---X---------------| (wraparound)
            //
            // but *not* in these cases
            //
            // 0 |-----------S---X--E------------| (wraparound)
            //
            // 0 |-----------|---X---------------| (wraparound)
            //             ^-S+E
            //
            // 0 |-----------S---|---------------| (wraparound)
            //             X+E-^
            //
            // or, on other words, iff !(S <= E <=X)
            if end >= start && end <= x {
                return false;
            }
        }
        Ordering::Greater => {
            // we have the opposite of above:
            //
            // 0 |-----------X---S---------------| (wraparound)
            //
            // X is between S and E (S < X < E) *only* in this case:
            //
            // 0 |-----------X---E--S------------| (wraparound)
            //
            // but *not* in these cases
            //
            // 0 |-----------X---S--E------------| (wraparound)
            //
            // 0 |--------E--X---S---------------| (wraparound)
            //
            // 0 |-----------|---S---------------| (wraparound)
            //               ^-X+E
            //
            // 0 |-----------X---|---------------| (wraparound)
            //               S+E-^
            //
            // or, on other words, iff S < E < X
            if end < start && end > x {
            } else {
                return false;
            }
        }
    }

    true
}
