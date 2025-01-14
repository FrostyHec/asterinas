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

pub struct ArgsConst; 
impl ArgsConst {
    pub const DEVICE:DeviceArgsConst = DeviceArgsConst;
    pub const OPERATION: OperationArgsConst = OperationArgsConst;
}
pub struct DeviceArgsConst;
impl DeviceArgsConst{
    pub const FIELD_NAME: &str = "device";
    pub const  DEFAULT_NAME:&str = "DEFAULT";
}

pub struct OperationArgsConst;
impl OperationArgsConst{
    pub const FIELD_NAME: &str = "op";
    pub const CREATE_SESSION_NAME:&str ="create";
    pub const DESTROY_SESSION_NAME:&str = "destroy";
    pub const STATEFUL_OP_NAME:&str = "stateful";
    pub const STATELESS_OP_NAME:&str = "stateless";
}






pub trait VirtIOCryptoDevice: Send + Sync + Any + Debug {
    fn create_sesson(&self,args:BTreeMap<String,String>);
    fn destroy_session(&self,args:BTreeMap<String,String>);
    fn stateful_operation(&self,args:BTreeMap<String,String>);
    fn stateless_operation(&self,args:BTreeMap<String,String>);
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
