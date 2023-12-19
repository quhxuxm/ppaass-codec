use crate::error::CodecError;
use bytes::{Buf, BytesMut};
use log::trace;
use std::mem::size_of;

pub mod agent;
pub mod proxy;

/// then 1 byte for compress flag,
/// then the length of the whole message
const HEADER_LENGTH: usize = size_of::<u8>() + size_of::<u64>();
/// The compress flag
const COMPRESS_FLAG: u8 = 1;
/// The uncompressed flag
const UNCOMPRESSED_FLAG: u8 = 0;

/// The decoder status
enum DecodeStatus {
    Head,
    Data(bool, u64),
}

fn decode_header(src: &mut BytesMut) -> Result<Option<(bool, u64)>, CodecError> {
    if src.len() < HEADER_LENGTH {
        trace!(
            "Input message is not enough to decode header, header length: {}",
            src.len()
        );
        src.reserve(HEADER_LENGTH);
        return Ok(None);
    }
    let compressed = src.get_u8() == 1;
    let body_length = src.get_u64();
    src.reserve(body_length as usize);
    trace!("The body length of the input message is: {body_length}");
    Ok(Some((compressed, body_length)))
}
