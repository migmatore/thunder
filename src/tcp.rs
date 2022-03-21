use std::io;

pub enum State {
    //Listen,
    SybnRcvd,
    Estab,
    FinWait1,
    FinWait2,
    TimeWait,
}

impl State {
    fn is_synchronized(&self) -> bool {
        match *self {
            State::SybnRcvd => false,
            State::Estab | State::FinWait1 | State::FinWait2 | State::TimeWait => true,
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
        let wnd = 1024;

        let mut c = Connection {
            state: State::SybnRcvd,
            send: SendSequenceSpace {
                iss,
                una: iss,
                nxt: iss + 1,
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

        c.tcp.syn = true;
        c.tcp.ack = true;

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

        self.ip
            .set_payload_len(size - self.ip.header_len() as usize);

        // the kernel does this for us
        self.tcp.checksum = self
            .tcp
            .calc_checksum_ipv4(&self.ip, &[])
            .expect("filed to compute ckecksum");

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
        eprintln!("got packet");
        // first, check that sequence numbers are valid
        let seqn = tcp_header.sequence_number();

        let mut slen = data.len() as u32;

        if tcp_header.fin() {
            slen += 1;
        }

        if tcp_header.syn() {
            slen += 1;
        }

        let w_end = self.recv.nxt.wrapping_add(self.recv.wnd as u32);

        let okay = if slen == 0 {
            // zero-length segment has separate rules for acceptance
            if self.recv.wnd == 0 {
                if seqn != self.recv.nxt {
                    false
                } else {
                    true
                }
            } else if !is_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn, w_end) {
                false
            } else {
                true
            }
        } else {
            if self.recv.wnd == 0 {
                return Ok(());
            } else if !is_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn, w_end)
                && !is_between_wrapped(
                    self.recv.nxt.wrapping_sub(1),
                    seqn.wrapping_add(slen - 1),
                    w_end,
                )
            {
                false
            } else {
                true
            }
        };

        if !okay {
            self.write(nic, &[])?;
            return Ok(());
        }

        self.recv.nxt = seqn.wrapping_add(slen);

        if !tcp_header.ack() {
            return Ok(());
        }

        //
        // acceptable ack check
        // SND.UNA < SEG.ACK =< SND.NXT
        // but remember wrapping!
        //

        let ackn = tcp_header.acknowledgment_number();

        if let State::SybnRcvd = self.state {
            if is_between_wrapped(
                self.send.una.wrapping_sub(1),
                ackn,
                self.send.nxt.wrapping_add(1),
            ) {
                // must have ACKed our SYN, since we detected at least one acked byte,
                // and we have only sent one byte (the SYN).
                self.state = State::Estab;
            } else {
                // TODO: <SEQ=SEG.ACK><CTL=RST>
            }
        }

        if let State::Estab | State::FinWait1 | State::FinWait2 = self.state {
            if !is_between_wrapped(self.send.una, ackn, self.send.nxt.wrapping_add(1)) {
                return Ok(());
                // return Err(io::Error::new(
                //     io::ErrorKind::BrokenPipe,
                //     "tried to ack unset byte",
                // ));
            }

            self.send.una = ackn;

            // TODO
            assert!(data.is_empty());

            if let State::Estab = self.state {
                // now let's terminate the connection!
                // TODO: needs to be stored in the retransmission queue!
                self.tcp.fin = true;
                self.write(nic, &[])?;
                self.state = State::FinWait1;    
            }
        }

        if let State::FinWait1 = self.state {
            if self.send.una == self.send.iss + 2 {
                // our FIN has been ACKed!
                self.state = State::FinWait2
            }
        }

        if tcp_header.fin() {
            match self.state {
                State::FinWait2 => {
                    // we're done with the connection
                    self.write(nic, &[])?;
                    self.state = State::TimeWait;
                }
                _ => unimplemented!(),
            }
        }

        Ok(())
    }
}

fn wrapping_it(lhs: u32, rhs: u32) -> bool {
    lhs.wrapping_sub(rhs) > 2^31
}

fn is_between_wrapped(start: u32, x: u32, end: u32) -> bool {
    wrapping_it(start, x) && wrapping_it(x, end)
}