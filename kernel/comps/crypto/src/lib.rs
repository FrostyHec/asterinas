// SPDX-License-Identifier: MPL-2.0

#![no_std]
#![deny(unsafe_code)]
#![feature(fn_traits)]

extern crate alloc;

use alloc::{collections::BTreeMap, fmt::Debug, string::{String, ToString}, sync::Arc, vec::Vec};
use core::any::Any;

use component::{init_component, ComponentInitError};
use ostd::sync::SpinLock;
use spin::Once;

pub static DEFAULT_NAME:&str = "DEFAULT";

pub trait VirtIOCryptoDevice: Send + Sync + Any + Debug {
    fn create_sesson(&self)->id;
    // fn destroy_session(id:usize);
    // fn stateful_encrypt();
    // fn stateless_encrypt();
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

pub fn get_device(name: &str) -> Arc<dyn VirtIOCryptoDevice>{
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
