use core::{hint::spin_loop, iter::Map};

use alloc::{boxed::Box, collections::btree_map::BTreeMap, sync::Arc, vec};
use aster_bigtcp::device;
use aster_crypto::{register_device, ArgsConst, VirtIOCryptoDevice};
use log::debug;
use ostd::{boot::BootloaderAcpiArg, mm::{DmaDirection, DmaStream, DmaStreamSlice, FrameAllocOptions, VmReader, VmWriter, PAGE_SIZE}, sync::SpinLock, Pod};

use crate::{device::{crypto::{self, header::*, session::{self, *}}, VirtioDeviceError}, queue::VirtQueue, transport::{ConfigManager, VirtioTransport}};

use super::config::{FeatureBits, VirtioCryptoConfig};

fn bytes_into_dma(bytes: &[u8], init: bool) -> DmaStreamSlice<DmaStream> {
    let vm_segment = FrameAllocOptions::new((bytes.len()-1) / PAGE_SIZE + 1).alloc_contiguous().unwrap();
    let stream = DmaStream::map(vm_segment, DmaDirection::Bidirectional, false).unwrap();
    if init {
        let mut writer = stream.writer().unwrap();
        writer.write(&mut VmReader::from(bytes));
    }
    DmaStreamSlice::new(stream, 0, bytes.len())
}

pub struct Device<'a> {
    device: CryptoDevice,
    session_map: BTreeMap<u64, CryptoSessionEnum<'a>>,
}

#[derive(Debug)]
pub struct CryptoDevice {
    config_manager: ConfigManager<VirtioCryptoConfig>,
    transport: SpinLock<Box<dyn VirtioTransport>>,

    pub data_queue: SpinLock<VirtQueue>,
    pub control_queue: SpinLock<VirtQueue>,

    pub features: FeatureBits,
}
impl VirtIOCryptoDevice for CryptoDevice{
    fn create_sesson(&self,args:BTreeMap<alloc::string::String,alloc::string::String>) {
        todo!()
    }
    fn destroy_session(&self,args:BTreeMap<alloc::string::String,alloc::string::String>) {
        todo!()
    }

    fn stateful_operation(&self,args:BTreeMap<alloc::string::String,alloc::string::String>) {
        todo!()
    }

    fn stateless_operation(&self,args:BTreeMap<alloc::string::String,alloc::string::String>) {
        todo!()
    }

}


impl CryptoDevice {
    pub fn negotiate_features(features: u64) -> u64 {
        debug!("crypto features {:?}", features);
        features
    }

    pub fn init(mut transport: Box<dyn VirtioTransport>) -> Result<(), VirtioDeviceError> {
        let config_manager = VirtioCryptoConfig::new_manager(transport.as_ref());
        let config = config_manager.read_config();
        debug!("virtio_crypto_config = {:?}", config);

        const QUEUE_SIZE: u16 = 64;
        let data_queue =
            SpinLock::new(VirtQueue::new(0, QUEUE_SIZE, transport.as_mut()).unwrap());
        let control_queue =
            SpinLock::new(VirtQueue::new(config.max_dataqueues as u16, QUEUE_SIZE, transport.as_mut()).unwrap());

        let device = CryptoDevice {
            config_manager,
            transport: SpinLock::new(transport),
            data_queue,
            control_queue,
            features: FeatureBits::empty(),
        };
        device.transport.lock().finish_init();

        let mut d = Device {
            device,
            session_map: BTreeMap::new(),
        };

        execute_testcases(&device);
        register_device(ArgsConst::DEVICE::DEFAULT_NAME, Arc::new(device));

        Ok(())
    }

    // fn request_by_bytes(&self, in_bytes: &[u8], out_bytes: &mut [u8]) -> usize {
    //     let mut queue = self.data_queue.disable_irq().lock();

    //     let in_dma = bytes_into_dma(in_bytes, true);
    //     let out_dma = bytes_into_dma(out_bytes, false);
    //     let token = queue
    //         .add_dma_buf(&[&in_dma], &[&out_dma])
    //         .expect("add queue failed");
    //     if queue.should_notify() {
    //         queue.notify();
    //     }
    //     while !queue.can_pop() {
    //         spin_loop();
    //     }
    //     queue.pop_used_with_token(token).expect("pop used failed");
    //     out_dma.sync().expect("sync failed");
    //     out_dma.reader().expect("get reader error").read(&mut VmWriter::from(out_bytes))
    // }
}

