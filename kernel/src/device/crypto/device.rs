// SPDX-License-Identifier: MPL-2.0

#![allow(unused_variables)]


use core::{cmp, sync::atomic::{AtomicBool, Ordering}};

use alloc::format;
use aster_crypto::{args_const, get_device};
use ostd::early_println;

use crate::{
    events::IoEvents,
    fs::{
        device::{Device, DeviceId, DeviceType},
        inode_handle::FileIo,
    },
    prelude::*,
    process::signal::{PollHandle, Pollable},
};

struct CryptoFile{
    read_buf:SpinLock<Vec<u8>>
}
impl CryptoFile{
    fn read_buf(&self,size:usize)->Vec<u8>{
        let bytes_to_read = cmp::min(size, self.read_buf.lock().len());
        self.read_buf.lock()[..bytes_to_read].to_vec()
    }

    fn clear_buf(&self){
        self.read_buf.lock().clear();
    }
    pub fn append_buf(&self, new_data: &[u8]) {
        self.read_buf.lock().extend_from_slice(new_data); 
    }
}

static CRYPTO_FILE:CryptoFile = CryptoFile{
    read_buf:SpinLock::new(Vec::new()),
};

pub struct Crypto;

impl Crypto {
    pub fn execute(args:BTreeMap<String,String>) {        
        let default_device_name = args_const::device::DEFAULT_NAME.to_string();
        let device_name = args.get(args_const::device::FIELD_NAME).unwrap_or(
            &default_device_name);
        let device = get_device(device_name);
        let op = match args.get(args_const::operation::FIELD_NAME) {
            Some(op) => op,
            None => {
                early_println!("Operation Not Found");
                return;
            }
        };
       match op.as_str(){
            args_const::operation::CREATE_SESSION_NAME =>{
                let out:u64;
                match device.create_sesson(args){
                    Ok(res) => out = res,
                    Err(_) => return,
                };
                debug!("Created Session: {:?}",out);
                CRYPTO_FILE.clear_buf();
                CRYPTO_FILE.append_buf(format!("{}", out).as_bytes());
            }
            args_const::operation::DESTROY_SESSION_NAME =>{
                match device.destroy_session(args){
                    Ok(_) => {
                        debug!("Session destroyed successfully")
                    },
                    Err(_) => return,
                }
            }
            args_const::operation::STATEFUL_OP_NAME =>{
                let out:Box<[u8]>;
                match device.stateful_operation(args){
                    Ok(res) => {
                        out = res;
                        debug!("operation output {:?}",out)
                    },
                    Err(_) => return,
                };
                CRYPTO_FILE.clear_buf();
                CRYPTO_FILE.append_buf(&out);
            }
            args_const::operation::STATELESS_OP_NAME =>{
                let out:Box<[u8]>;
                match device.stateless_operation(args){
                    Ok(res) => {
                        out = res;
                        early_println!("operation output {:?}",out)
                    },
                    Err(_) => return,
                };
                CRYPTO_FILE.clear_buf();
                CRYPTO_FILE.append_buf(&out);
            }
            _ =>{
                early_println!("Unknown operation type: {:?}",op)
            }
       }
    }
}

impl Device for Crypto {
    fn type_(&self) -> DeviceType {
        DeviceType::CharDevice
    }

    fn id(&self) -> DeviceId {
        DeviceId::new(1, 10)
    }

    fn open(&self) -> Result<Option<Arc<dyn FileIo>>> {
        Ok(Some(Arc::new(Crypto)))
    }
}

impl Pollable for Crypto {
    fn poll(&self, mask: IoEvents, poller: Option<&mut PollHandle>) -> IoEvents {
        let events = IoEvents::IN | IoEvents::OUT;
        events & mask
    }
}

impl FileIo for Crypto {
    fn read(&self, writer: &mut VmWriter) -> Result<usize> {
        let buf = CRYPTO_FILE.read_buf(writer.avail());
        let size = writer.write_fallible(&mut buf.as_slice().into())?;
        Ok(size)
    }

    fn write(&self, reader: &mut VmReader) -> Result<usize> {
        let mut buffer = vec![0; reader.remain()];
        let bytes_read = reader.read_fallible(&mut buffer.as_mut_slice().into())
            .map_err(|(err, _)| err).unwrap();

        let input = String::from_utf8(buffer).unwrap();
        let args = parse_kv_pairs(&input);
        Crypto::execute(args);
        Ok(bytes_read)
    }
}

fn parse_kv_pairs(input: &str) -> BTreeMap<String, String> {
    // split by comma ',' and seperate by first eq-op '=', like key=value
    let mut kv_map = BTreeMap::new();
    
    let parts = input.split(",");
    
    for part in parts {
        if let Some(equal_index) = part.find('=') {
            let key = &part[..equal_index].to_lowercase();
            let value = &part[equal_index + 1..];
            kv_map.insert(key.to_string(), value.to_string());
        }
    }
    kv_map
}