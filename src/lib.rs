use std::collections::HashMap;
use std::io;
use std::io::prelude::*;
use std::sync::mpsc;
use std::thread;

#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
struct Quad {
    src: (Ipv4Addr, u16),
    dst: (Ipv4Addr, u16),
}

type InterfaceHandle = mpsc::Sender<InterfaceRequest>;

enum InterfaceRequest {
    Write {
        quad: Quad,
        bytes: Vec<u8>,
        ack: mpsc::Sender<usize>,
    },
    Flush {
        quad: Quad,
        ack: mpsc::Sender<()>,
    },
    Bind {
        port: u16,
        ack: mpsc::Sender<()>,
    },
    Unbind,
    Read {
        quad: Quad,
        max_length: usize,
        read: mpsc::Sender<Vec<u8>>,
    },
    Accept {
        port: u16,
        ack: mpsc::Sender<Quad>,
    }
}

pub struct Interface {
    tx: InterfaceHandle,
    jh: thread::JoinHandle<()>,
}
struct ConnectionManager {
    connections: HashMap<Quad, tcp::Connection>,
    nic: tun_tap::Iface,
    buf: [u8; 1504],
}

impl ConnectionManager {
    fn run_on(self, rx: mpsc::Sender<InterfaceRequest>) {
        // main event loop for packet processing
        for req in rx {}
    }
}

impl Interface {
    pub fn new() -> io::Result<Self> {
        let cm = ConnectionManager {
            connections: Default::default(),
            nic: tun_tap::Iface::without_packet_info("tun0", tun_tap::Mode::Tun)?,
            buf: [0u8; 1504],
        };

        let (tx, rx) = mpsc::channel();

        let jh = thread::spawn(move || cm.run_on(rx));

        Ok(Interface { tx, jh })
    }

    pub fn bind(&mut self, port: u16) -> io::Result<TcpListener> {
        let (ack, rx) = mpsc::channel();

        self.tx.send(InterfaceRequest::Bind { port, ack });

        rx.recv().unwrap();

        Ok(TcpListener(port, self.tx.clone()))
    }
}

pub struct TcpListener(u16, InterfaceHandle);

impl TcpListener {
    pub fn accept(&mut self) -> io::Result<TcpStream> {
        let (ack, rx) = mpsc::channel();

        self.1.send(InterfaceRequest::Accept {
            port: self.0,
            ack,
        });

        let quad = rx.recv().unwrap();

        Ok(TcpStream(quad, self.1.clone()))
    }
}

pub struct TcpStream(Quad, InterfaceHandle);

impl Read for TcpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let (read, rx) = mpsc::channel();

        self.1.send(InterfaceRequest::Read {
            max_length: buf.len(),
            read,
        });

        let bytes = rx.recv().unwrap();

        assert!(bytes.len() <= buf.len());

        buf.copy_from_slice(&bytes[..]);

        Ok(bytes.len())
    }
}

impl Write for TcpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let (ack, rx) = mpsc::channel();

        self.1.send(InterfaceRequest::Write {
            bytes: Vec::from(buf),
            ack,
        });

        let n = rx.recv().unwrap();

        assert!(n <= buf.len());

        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        let (ack, rx) = mpsc::channel();

        self.1.send(InterfaceRequest::Flush { ack });

        rx.recv().unwrap();

        Ok(())
    }
}
