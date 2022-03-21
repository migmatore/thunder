use std::io;
use std::io::prelude::*;

pub struct Interface {}

impl Default for Interface {
    fn default() -> Self {
        let mut connections: HashMap<Quad, tcp::Connection> = Default::default();
        
        let mut nic = Iface::without_packet_info("tun0", Mode::Tun)?;

        let mut buf = [0u8; 1504];

        Interface {
            connections, nic, buf
        }
    }
}

pub struct TcpStream {}

impl Read for TcpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {}
}

impl Write for TcpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {}

    fn flush(&mut self) -> io::Result<()> {}
}

pub struct TcpListener {}

impl TcpListener {
    pub fn accept(&mut self) -> io::Result<TcpStream> {}
}
