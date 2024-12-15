use alloc::{boxed::Box, sync::Arc};
use log::debug;
use ostd::sync::SpinLock;

use crate::{device::VirtioDeviceError, queue::VirtQueue, transport::{ConfigManager, VirtioTransport}};

use super::config::VirtioFileSystemConfig;

pub struct FileSystemDevice {
    config_manager: ConfigManager<VirtioFileSystemConfig>,
    transport: SpinLock<Box<dyn VirtioTransport>>,
    receive_queue: SpinLock<VirtQueue>,
    transmit_queue: SpinLock<VirtQueue>,
}

impl FileSystemDevice {
    pub fn negotiate_features(features: u64) -> u64 {
        features
    }

    pub fn init(mut transport: Box<dyn VirtioTransport>) -> Result<(), VirtioDeviceError> {
        let config_manager = VirtioFileSystemConfig::new_manager(transport.as_ref());
        debug!("virtio_fs_config = {:?}", config_manager.read_config());

        // Initalize the request virtqueue
        const RECV0_QUEUE_INDEX: u16 = 0;
        const TRANSMIT0_QUEUE_INDEX: u16 = 1;
        let receive_queue =
            SpinLock::new(VirtQueue::new(RECV0_QUEUE_INDEX, 2, transport.as_mut()).unwrap());
        let transmit_queue =
            SpinLock::new(VirtQueue::new(TRANSMIT0_QUEUE_INDEX, 2, transport.as_mut()).unwrap());

        let device = Arc::new(Self {
            config_manager,
            transport: SpinLock::new(transport),
            receive_queue,
            transmit_queue,
        });
        
        Ok(())
    }

}

