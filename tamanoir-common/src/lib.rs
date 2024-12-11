#![no_std]

#[derive(Clone, Copy)]
#[repr(C)]
pub enum ContinuationByte {
    Reset = 0,
    ResetEnd = 1,
    Continue = 2,
    End = 3,
}
impl ContinuationByte {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(ContinuationByte::Reset),
            1 => Some(ContinuationByte::ResetEnd),
            2 => Some(ContinuationByte::Continue),
            3 => Some(ContinuationByte::End),
            _ => None,
        }
    }
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct RceEvent {
    pub prog: [u8; 32],
    pub event_type: ContinuationByte,
    pub length: usize,
    pub is_first_batch: bool,
    pub is_last_batch: bool,
}

impl RceEvent {
    pub const LEN: usize = core::mem::size_of::<RceEvent>();
    pub fn payload(&self) -> &[u8] {
        &self.prog[..self.length]
    }
}
