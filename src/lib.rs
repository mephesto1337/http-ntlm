pub trait NtlmVersion {
    fn version() -> u32;
}

//pub mod client;
mod crypto;
pub mod messages;
