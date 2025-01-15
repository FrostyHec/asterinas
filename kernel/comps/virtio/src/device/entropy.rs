use alloc::{boxed::Box, sync::Arc};

use ostd::{
    mm::{DmaDirection, DmaStream, FrameAllocOptions},
    sync::SpinLock,
};

use super::VirtioDeviceError;
use crate::{queue::VirtQueue, transport::VirtioTransport};

pub struct EntropyDevice {
    request_buffer: DmaStream,
    request_queue: SpinLock<VirtQueue>,
    transport: SpinLock<Box<dyn VirtioTransport>>,
}

impl EntropyDevice {
    pub fn negotiate_features(features: u64) -> u64 {
        features
    }
    pub fn init(mut transport: Box<dyn VirtioTransport>) -> Result<(), VirtioDeviceError> {
        // Initalize the request virtqueue
        const REQUEST_QUEUE_INDEX: u16 = 0;
        let request_queue =
            SpinLock::new(VirtQueue::new(REQUEST_QUEUE_INDEX, 1, transport.as_mut()).unwrap());
        // Initalize the request buffer
        let request_buffer = {
            let vm_segment = FrameAllocOptions::new(1).alloc_contiguous().unwrap();
            DmaStream::map(vm_segment, DmaDirection::FromDevice, false).unwrap()
        };
        // Create device
        let device = Arc::new(Self {
            request_buffer,
            request_queue,
            transport: SpinLock::new(transport),
        });
        // Finish init
        device.transport.lock().finish_init();
        // Test device
        // test_device(device);
        Ok(())
    }
}
