use std::{
    io,
    sync::{atomic::AtomicBool, mpsc::Sender, Arc},
    thread,
    time::Duration,
};

use std::os::fd::AsRawFd;

use aya::{
    maps::{ring_buf::RingBufItem, MapData, RingBuf},
    programs::KProbe,
    Ebpf,
};

use mio::{event::Source, unix::SourceFd, Events, Interest, Poll, Registry, Token};

pub struct RingBuffer<'a> {
    pub buffer: RingBuf<&'a mut MapData>,
}

impl<'a> RingBuffer<'a> {
    fn new(ebpf: &'a mut Ebpf) -> Self {
        let buffer = RingBuf::try_from(ebpf.map_mut("DATA").unwrap()).unwrap();
        Self { buffer }
    }

    fn next(&mut self) -> Option<RingBufItem<'_>> {
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

pub fn load(data_sender: Sender<u32>, terminate: Arc<AtomicBool>) {
    thread::spawn(move || {
        let rlim = libc::rlimit {
            rlim_cur: libc::RLIM_INFINITY,
            rlim_max: libc::RLIM_INFINITY,
        };
        unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };

        let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/tamanoir"
        )))
        .unwrap();

        let program: &mut KProbe = ebpf.program_mut("tamanoir").unwrap().try_into().unwrap();

        program.load().unwrap();
        program.attach("input_handle_event", 0).unwrap();

        let mut poll = Poll::new().unwrap();
        let mut events = Events::with_capacity(128);

        let mut ring_buf = RingBuffer::new(&mut ebpf);

        poll.registry()
            .register(
                &mut SourceFd(&ring_buf.buffer.as_raw_fd()),
                Token(0),
                Interest::READABLE,
            )
            .unwrap();

        loop {
            poll.poll(&mut events, Some(Duration::from_millis(100)))
                .unwrap();
            if terminate.load(std::sync::atomic::Ordering::Relaxed) {
                break;
            }
            for event in &events {
                if terminate.load(std::sync::atomic::Ordering::Relaxed) {
                    break;
                }
                if event.token() == Token(0) && event.is_readable() {
                    if terminate.load(std::sync::atomic::Ordering::Relaxed) {
                        break;
                    }
                    while let Some(item) = ring_buf.next() {
                        if terminate.load(std::sync::atomic::Ordering::Relaxed) {
                            break;
                        }
                        let key: [u8; 4] = item.to_owned().try_into().unwrap();
                        let key: u32 = u32::from_ne_bytes(key);
                        data_sender.send(key).ok();
                    }
                }
            }
        }

        let _ = poll
            .registry()
            .deregister(&mut SourceFd(&ring_buf.buffer.as_raw_fd()));
    });
}
