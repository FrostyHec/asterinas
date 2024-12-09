use alloc::boxed::Box;
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
        const REQUEST_QUEUE_INDEX: u16 = 0;
        // Create device
        // let device = Arc::new(Self {

        //     transport: SpinLock::new(transport),
        // });
        // Finish init
        // device.transport.lock().finish_init();
        // Test device
        Ok(())
    }
}

