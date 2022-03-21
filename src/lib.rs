use std::io;
use std::io::prelude::*;

pub struct TcpStream {}

impl Read for TcpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize>;
}

impl Write for TcpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize>;

    fn flush(&mut self) -> io::Result<()>;
}

pub struct TcpListener {}

impl TcpListener {
    pub fn accept(&mut self) -> io::Result<TcpStream> {

    }
}