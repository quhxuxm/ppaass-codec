pub mod agent;
pub mod proxy;

enum DecodeStatus {
    Head,
    Data(bool, u64),
}
