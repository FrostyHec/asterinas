// SPDX-License-Identifier: MPL-2.0

#![allow(unused_variables)]


use aster_crypto::{get_device, DEFAULT_NAME};

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
pub struct Crypto;

impl Crypto {
    pub fn create_session(device_name:&str) {
        let device = get_device(device_name);
        device.create_sesson();
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
        Ok(0)
    }

    fn write(&self, reader: &mut VmReader) -> Result<usize> {
        let mut buffer = vec![0; reader.remain()];
        let bytes_read = reader.read_fallible(&mut buffer.as_mut_slice().into())
            .map_err(|(err, _)| err).unwrap();

        let input = String::from_utf8(buffer).unwrap();
        early_println!("input str {:?}",input);
        Crypto::create_session(DEFAULT_NAME);
        Ok(bytes_read)
    }
}
