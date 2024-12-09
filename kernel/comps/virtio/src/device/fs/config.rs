use core::mem::offset_of;

use aster_util::safe_ptr::SafePtr;
use ostd::Pod;

use crate::transport::{ConfigManager, VirtioTransport};

#[derive(Debug, Pod, Clone, Copy)]
#[repr(C)]
pub struct VirtioFileSystemConfig {
    pub tag: [u8; 36],
    pub num_request_queues: u32,
    pub notify_buf_size: u32,
}

impl VirtioFileSystemConfig {
    pub(super) fn new_manager(transport: &dyn VirtioTransport) -> ConfigManager<Self> {
        let safe_ptr = transport
            .device_config_mem()
            .map(|mem| SafePtr::new(mem, 0));
        let bar_space = transport.device_config_bar();
        ConfigManager::new(safe_ptr, bar_space)
    }
}

impl ConfigManager<VirtioFileSystemConfig> {
    pub(super) fn read_config(&self) -> VirtioFileSystemConfig {
        let mut fs_config = VirtioFileSystemConfig::new_uninit();

        for i in 0..36 {
            fs_config.tag[i] = self
                .read_once::<u8>(offset_of!(VirtioFileSystemConfig, tag) + i)
                .unwrap();
        }
        fs_config.num_request_queues = self
            .read_once::<u32>(offset_of!(VirtioFileSystemConfig, num_request_queues))
            .unwrap();
        fs_config.notify_buf_size = self
            .read_once::<u32>(offset_of!(VirtioFileSystemConfig, notify_buf_size))
            .unwrap();

        fs_config
    }
}