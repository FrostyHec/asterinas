// SPDX-License-Identifier: MPL-2.0

#![no_std]
#![deny(unsafe_code)]
#![feature(fn_traits)]

extern crate alloc;

use alloc::{
    boxed::Box, collections::BTreeMap, fmt::Debug, string::{String, ToString}, sync::Arc, vec::Vec
};
use core::any::Any;

use component::{init_component, ComponentInitError};
use ostd::sync::SpinLock;
use spin::Once;

pub mod args_const {
    pub mod device {
        pub const FIELD_NAME: &str = "device";
        pub const DEFAULT_NAME: &str = "DEFAULT";
    }
    pub mod operation {
        pub const FIELD_NAME: &str = "op";
        pub const CREATE_SESSION_NAME: &str = "create";
        pub const DESTROY_SESSION_NAME: &str = "destroy";
        pub const STATEFUL_OP_NAME: &str = "stateful";
        pub const STATELESS_OP_NAME: &str = "stateless";
    }
    pub mod service {
        pub const FIELD_NAME: &str = "service";
        pub const HASH_NAME: &str = "hash";
        pub const MAC_NAME: &str = "mac";
        pub const SYM_CIPHER_NAME: &str = "cipher";
        pub const SYM_ALGO_CHAIN_NAME: &str = "sym-algo";
        pub const AEAD_NAME: &str = "aead";
        pub const AKCIPHER_NAME: &str = "akcipher";
    }
    pub const KEY_FIELD_NAME: &str = "key";
    pub const ALGO_FIELD_NAME: &str = "algo";
    pub const SESSION_ID_FIELD_NAME:&str = "id";
    pub mod algo {
        pub mod cipher {
            pub const AES_ECB: &str = "aes_ecb";
        }
    }
    pub mod session_op{
        pub const FIELD_NAME:&str = "session-op";
        pub const ENCRYPT_NAME:&str  = "encrypt";
        pub const DECRYPT_NAME:&str  = "decrypt";
    }
    pub const IV_FIELD_NAME:&str = "iv";
    pub const SRC_FIELD_NAME:&str = "src-data";
    pub const OUT_LEN_NAME:&str = "out-len";
}

pub trait VirtIOCryptoDevice: Send + Sync + Any + Debug {
    fn create_sesson(&self, args: BTreeMap<String, String>) -> Result<u64, &str>;
    fn destroy_session(&self, args: BTreeMap<String, String>)->Result<(),&str>;
    fn stateful_operation(&self, args: BTreeMap<String, String>)->Result<Box<[u8]>,&str>;
    fn stateless_operation(&self, args: BTreeMap<String, String>)->Result<Box<[u8]>,&str>;
}

pub fn register_device(name: &str, device: Arc<dyn VirtIOCryptoDevice>) {
    COMPONENT
        .get()
        .unwrap()
        .crypto_device_table
        .disable_irq()
        .lock()
        .insert(name.to_string(), device);
}

pub fn get_device(name: &str) -> Arc<dyn VirtIOCryptoDevice> {
    let crypto_devs = COMPONENT
        .get()
        .unwrap()
        .crypto_device_table
        .disable_irq()
        .lock();
    crypto_devs.get(&name.to_string()).unwrap().clone()
}

pub fn all_devices() -> Vec<(String, Arc<dyn VirtIOCryptoDevice>)> {
    let crypto_devs = COMPONENT
        .get()
        .unwrap()
        .crypto_device_table
        .disable_irq()
        .lock();
    crypto_devs
        .iter()
        .map(|(name, device)| (name.clone(), device.clone()))
        .collect()
}

static COMPONENT: Once<Component> = Once::new();

#[init_component]
fn component_init() -> Result<(), ComponentInitError> {
    let a = Component::init()?;
    COMPONENT.call_once(|| a);
    Ok(())
}

#[derive(Debug)]
struct Component {
    crypto_device_table: SpinLock<BTreeMap<String, Arc<dyn VirtIOCryptoDevice>>>,
}

impl Component {
    pub fn init() -> Result<Self, ComponentInitError> {
        Ok(Self {
            crypto_device_table: SpinLock::new(BTreeMap::new()),
        })
    }
}
