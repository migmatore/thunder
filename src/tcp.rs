pub enum State {
    Closed,
    Listen,
    SybnRcvd,
    Estab,
}

impl Default for State {
    fn default() -> Self {
        //State::Closed
        State::Listen
    }
}

impl State {
    pub fn on_packet<'a>(
        &mut self,
        ip_header: etherparse::Ipv4HeaderSlice<'a>,
        tcp_header: etherparse::TcpHeaderSlice<'a>,
        data: &'a [u8],
    ) {
        match *self {
            State::Closed => {
                return;
            }
            Self::Listen => {
                if !tcp_header.syn() {
                    // only expected SYN packet
                    return;
                }

                // need to start establishing a connection
                let syn_ack = etherparse::TcpHeader::new(
                    tcp_header.destination_port(),
                    tcp_header.source_port(),
                    0,
                    0,
                );
            }
        }

        eprintln!(
            "{}:{} → {}:{} {}b of tcp",
            ip_header.source_addr(),
            tcp_header.source_port(),
            ip_header.destination_addr(),
            tcp_header.destination_port(),
            data.len()
        );
    }
}
