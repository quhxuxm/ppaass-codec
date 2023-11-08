use std::mem::size_of;

pub mod agent;
pub mod proxy;

/// Each ppaass message will start with a magic word "__PPAASS__"
const PPAASS_FLAG: &[u8] = "__PPAASS__".as_bytes();
/// Each ppaass message will start with the "__PPAASS__",
/// then 1 byte for compress flag,
/// then the length of the whole message
const HEADER_LENGTH: usize = PPAASS_FLAG.len() + size_of::<u8>() + size_of::<u64>();
/// The compress flag
const COMPRESS_FLAG: u8 = 1;
/// The uncompress flag
const UNCOMPRESS_FLAG: u8 = 0;

/// The decoder status
enum DecodeStatus {
    Head,
    Data(bool, u64),
}
