// SPDX-License-Identifier: MPL-2.0

#![allow(unused_variables)]


use core::cmp;

use aster_crypto::{get_device, ArgsConst, VirtIOCryptoDevice};

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
    is_device_busy:bool,
    read_buf:Vec<u8>
}

impl CryptoFile{
    fn set_device_busy(&mut self){
        self.is_device_busy = true;
    }
    fn set_device_free(&mut self){
        self.is_device_busy = false;
    }
    fn get_device_busy(&self)->bool{
        self.is_device_busy
    }

    fn read_all_buf(&self)->Vec<u8>{
        self.read_buf.clone()
    }

    fn read_buf(&self,size:usize)->Vec<u8>{
        let bytes_to_read = cmp::min(size, self.read_buf.len());
        self.read_buf[..bytes_to_read].to_vec()
    }

    fn clear_buf(&mut self){
        self.read_buf = Vec::new();
    }
    pub fn append_buf(&mut self, new_data: &[u8]) {
        self.read_buf.extend_from_slice(new_data); 
    }
}

static CRYPTO_FILE:CryptoFile = CryptoFile{
    is_device_busy:false,
    read_buf:Vec::new(),
};

pub struct Crypto;

impl Crypto {
    pub fn execute(args:BTreeMap<String,String>) {
        let default_device_name = ArgsConst::DEVICE::DEFAULT_NAME.to_string();
        let device_name = args.get(ArgsConst::FIELD_NAME).unwrap_or(
            &default_device_name);
        let device = get_device(device_name);
        let op = match args.get(ArgsConst::OPERATION::FIELD_NAME) {
            Some(op) => op,
            None => {
                early_println!("Operation Not Found");
                return;
            }
        };
       match op.as_str(){
            ArgsConst::OPERATION::CREATE_SESSION_NAME =>{
                device.create_sesson(args);
            }
            Args::OPERATION::DESTROY_SESSION_NAME =>{
                device.destroy_session(args);
            }
            Args::OPERATION::STATEFUL_OP_NAME =>{
                device.stateful_operation(args);
            }
            Args::OPERATION::STATELESS_OP_NAME =>{
                device.stateless_operation(args);
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
        early_println!("input str {:?}",input);
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