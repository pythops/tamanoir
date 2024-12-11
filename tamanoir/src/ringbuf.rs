use std::{io, mem, os::fd::AsRawFd};

use aya::{
    maps::{ring_buf::RingBufItem, MapData, RingBuf},
    Ebpf,
};
use mio::{event::Source, unix::SourceFd, Interest, Registry, Token};

pub struct RingBuffer<'a> {
    pub buffer: RingBuf<&'a mut MapData>,
}

impl<'a> RingBuffer<'a> {
    pub fn new(ebpf: &'a mut Ebpf) -> Self {
        let buffer = RingBuf::try_from(ebpf.map_mut("RBUF").unwrap()).unwrap();
        Self { buffer }
    }

    pub fn _next(&mut self) -> Option<RingBufItem<'_>> {
        self.buffer.next()
    }
}

impl Source for RingBuffer<'_> {
    fn register(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest,
    ) -> io::Result<()> {
        SourceFd(&self.buffer.as_raw_fd()).register(registry, token, interests)
    }

    fn reregister(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest,
    ) -> io::Result<()> {
        SourceFd(&self.buffer.as_raw_fd()).reregister(registry, token, interests)
    }

    fn deregister(&mut self, registry: &Registry) -> io::Result<()> {
        SourceFd(&self.buffer.as_raw_fd()).deregister(registry)
    }
}
#[derive(Clone, Debug, Copy)]
#[repr(C)]
pub enum ContinuationByte {
    Reset = 0,
    ResetEnd = 1,
    Continue = 2,
    End = 3,
}
#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct RceEvent {
    pub prog: [u8; 32],
    pub event_type: ContinuationByte,
    pub length: usize,
    pub is_first_batch: bool,
    pub is_last_batch: bool,
}

impl RceEvent {
    pub const LEN: usize = mem::size_of::<RceEvent>();
    pub fn payload(&self) -> &[u8] {
        &self.prog[..self.length]
    }
}
