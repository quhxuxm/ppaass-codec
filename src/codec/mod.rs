use crate::error::DecoderError;
use bytes::{Buf, BytesMut};
use log::trace;
use std::mem::size_of;

mod agent;
mod proxy;

/// Each ppaass message will start with a magic word "__PPAASS__"
const MAGIC_FLAG: &[u8] = "__PPAASS__".as_bytes();
/// Each ppaass message will start with the "__PPAASS__",
/// then 1 byte for compress flag,
/// then the length of the whole message
const HEADER_LENGTH: usize = MAGIC_FLAG.len() + size_of::<u8>() + size_of::<u64>();
/// The compress flag
const COMPRESS_FLAG: u8 = 1;
/// The uncompressed flag
const UNCOMPRESSED_FLAG: u8 = 0;

/// The decoder status
enum DecodeStatus {
    Head,
    Data(bool, u64),
}

fn decode_header(src: &mut BytesMut) -> Result<Option<(bool, u64)>, DecoderError> {
    if src.len() < HEADER_LENGTH {
        trace!(
            "Input message is not enough to decode header, header length: {}",
            src.len()
        );
        src.reserve(HEADER_LENGTH);
        return Ok(None);
    }
    let ppaass_flag = src.split_to(MAGIC_FLAG.len());
    if !MAGIC_FLAG.eq(&ppaass_flag) {
        return Err(DecoderError::Other(format!(
            "The incoming message is not begin with {:?}",
            MAGIC_FLAG
        )));
    }
    let compressed = src.get_u8() == 1;
    let body_length = src.get_u64();
    src.reserve(body_length as usize);
    trace!("The body length of the input message is {}", body_length);
    Ok(Some((compressed, body_length)))
}
