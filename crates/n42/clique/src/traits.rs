pub const  SIGNATURE_LENGTH :usize = 96;
pub type Signature = [u8; SIGNATURE_LENGTH];

pub const ADDRESS_LENGTH :usize = 20;
pub type Address = [u8; ADDRESS_LENGTH];
pub const HASH_LENGTH :usize = 32;
pub type Hash = [u8; HASH_LENGTH];

pub const  PUBLIC_KEY_LENGTH :usize = 48;
pub type PublicKey = [u8; PUBLIC_KEY_LENGTH];
// Verify 结构体定义
pub struct Verify {
    pub address: Address,
    pub public_key: PublicKey,
}

