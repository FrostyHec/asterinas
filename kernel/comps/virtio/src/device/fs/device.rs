use core::{hint::spin_loop};

use alloc::{boxed::Box, sync::Arc};
use log::debug;
use ostd::{mm::{DmaDirection, DmaStream, DmaStreamSlice, FrameAllocOptions, VmReader, VmWriter, PAGE_SIZE}, sync::SpinLock, Pod};

use crate::{device::{fs::header::{FuseInHeader, FuseInitIn, FuseOpcode, FuseOpenIn, FuseOutHeader, OpenFlags}, VirtioDeviceError}, queue::VirtQueue, transport::{ConfigManager, VirtioTransport}};

use super::config::VirtioFileSystemConfig;

pub struct FileSystemDevice {
    config_manager: ConfigManager<VirtioFileSystemConfig>,
    transport: SpinLock<Box<dyn VirtioTransport>>,

    hiprio_queue: SpinLock<VirtQueue>,
    request_queue: SpinLock<VirtQueue>,
}

fn bytes_into_dma(bytes: &[u8], init: bool) -> DmaStreamSlice<DmaStream> {
    let vm_segment = FrameAllocOptions::new(1).alloc_contiguous().unwrap();
    let stream = DmaStream::map(vm_segment, DmaDirection::Bidirectional, false).unwrap();
    if init {
        let mut writer = stream.writer().unwrap();
        writer.write(&mut VmReader::from(bytes));
    }
    DmaStreamSlice::new(stream, 0, bytes.len())
}

impl FileSystemDevice {
    pub fn negotiate_features(features: u64) -> u64 {
        if features==1 {
            log::warn!("Feature VIRTIO_FS_F_NOTIFICATION of Virtio fs unsupported")
        }
        0
    }

    pub fn init(mut transport: Box<dyn VirtioTransport>) -> Result<(), VirtioDeviceError> {
        let config_manager = VirtioFileSystemConfig::new_manager(transport.as_ref());
        debug!("virtio_fs_config = {:?}", config_manager.read_config());
        if config_manager.read_config().num_request_queues != 1 {
            // FIXME: support Multi-Queue Block IO Queueing Mechanism
            // (`BlkFeatures::MQ`) to accelerate multi-processor requests for
            // block devices. When SMP is enabled on x86, the feature is on.
            // We should also consider negotiating the feature in the future.
            // return Err(VirtioDeviceError::QueuesAmountDoNotMatch(num_queues, 1));
            log::warn!(
                "Not supporting Multi-Queue File system Queueing Mechanism, only using the first queue"
            );
        }
        // Initalize virtqueues
        const QID_HIPRIO: u16 = 0;
        const QID_REQUEST: u16 = 2;
        const QUEUE_SIZE: u16 = 64;
        let hiprio_queue =
            SpinLock::new(VirtQueue::new(QID_HIPRIO, QUEUE_SIZE, transport.as_mut()).unwrap());
        // let new_queue: SpinLock<VirtQueue> = SpinLock::new(VirtQueue::new(1, 0, transport.as_mut()).unwrap());
        let request_queue =
            SpinLock::new(VirtQueue::new(QID_REQUEST, QUEUE_SIZE, transport.as_mut()).unwrap());

        let device = Arc::new(Self {
            config_manager,
            transport: SpinLock::new(transport),
            hiprio_queue,
            request_queue,
        });
        
        let in_header = FuseInHeader { 
            len: (size_of::<FuseInHeader>() + size_of::<FuseInitIn>()) as u32, 
            opcode: FuseOpcode::FUSE_INIT as u32,
            unique: 0, 
            nodeid: 1,
            uid: 1,
            gid: 1, 
            pid: 1,
            padding: 0, 
        };
        let in_open = FuseOpenIn {
            flags: OpenFlags::empty(),
            unused: 0,
        };
        let out_header = FuseOutHeader::default();
        let out_open = FuseOpenIn::default();
        let in_packet = [in_header.as_bytes(), in_open.as_bytes()].concat();
        let mut out_packet = [out_header.as_bytes(), out_open.as_bytes()].concat();
        let out_packet = out_packet.as_mut_slice();

        device.request(in_packet.as_slice(), out_packet);
        
        debug!("{:?}", out_packet);

        Ok(())
    }

    fn request(&self, in_packet: &[u8], out_packet: &mut [u8]) -> usize {
        let mut queue = self.request_queue.disable_irq().lock();
        
        let in_dma = bytes_into_dma(in_packet, true);
        let out_dma = bytes_into_dma(out_packet, false);
        let token = queue
            .add_dma_buf(&[&in_dma], &[&out_dma])
            .expect("add queue failed");
        if queue.should_notify() {
            queue.notify();
        }
        while !queue.can_pop() {
            spin_loop();
        }
        queue.pop_used_with_token(token).expect("pop used failed");
        out_dma.sync().expect("sync failed");
        out_dma.reader().expect("get reader error").read(&mut VmWriter::from(out_packet))
    }
}

