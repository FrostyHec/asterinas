use core::hint::spin_loop;

use alloc::{boxed::Box, sync::Arc, vec};
use aster_bigtcp::device;
use log::debug;
use ostd::{mm::{DmaDirection, DmaStream, DmaStreamSlice, FrameAllocOptions, VmReader, VmWriter, PAGE_SIZE}, sync::SpinLock, Pod};

use crate::{device::{crypto::{self, header::*, session::*}, VirtioDeviceError}, queue::VirtQueue, transport::{ConfigManager, VirtioTransport}};

use super::{config::VirtioCryptoConfig};

fn bytes_into_dma(bytes: &[u8], init: bool) -> DmaStreamSlice<DmaStream> {
    let vm_segment = FrameAllocOptions::new((bytes.len()-1) / PAGE_SIZE + 1).alloc_contiguous().unwrap();
    let stream = DmaStream::map(vm_segment, DmaDirection::Bidirectional, false).unwrap();
    if init {
        let mut writer = stream.writer().unwrap();
        writer.write(&mut VmReader::from(bytes));
    }
    DmaStreamSlice::new(stream, 0, bytes.len())
}

#[derive(Debug)]
pub struct CryptoDevice {
    config_manager: ConfigManager<VirtioCryptoConfig>,
    transport: SpinLock<Box<dyn VirtioTransport>>,

    pub data_queue: SpinLock<VirtQueue>,
    pub control_queue: SpinLock<VirtQueue>,
}

impl CryptoDevice {
    pub fn negotiate_features(features: u64) -> u64 {
        debug!("cypto features {:?}", features);
        features
    }

    pub fn init(mut transport: Box<dyn VirtioTransport>) -> Result<(), VirtioDeviceError> {
        let config_manager = VirtioCryptoConfig::new_manager(transport.as_ref());
        let config = config_manager.read_config();
        debug!("virtio_fs_config = {:?}", config);

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
        };
        device.transport.lock().finish_init();

        let session = CryptoSession::<SymCipherSession>::new(
            &device, 
            &mut SymCipherCreateSessionFlf::new(
                CipherSessionFlf::new(
                    CipherAlgo::CIPHER_3DES_CBC, 
                    0, //auto filled 
                    CryptoOp::OP_DECRYPT,
                )
            ),
            &mut SymCipherCreateSessionVlf {
                cipher_key: "yv8.,7f 0,q7fhq 1u9ep,1 ".as_bytes().into(), //len should be (<= ?) 24 ?
            },
        ).unwrap();
        debug!("create end");

        let encrypt_out = session.basic_request(
            CipherOpcode::ENCRYPT, //TODO
            &mut SymCipherDataFlf::new(CipherDataFlf {
                iv_len: 0, src_data_len: 0, dst_data_len: 8, padding: 0,
            }), 
            &SymCipherDataVlfIn {
                iv: vec![0 as u8; 8].into_boxed_slice(), //len == 8 ? 
                src_data: vec![190, 147, 128, 144, 239, 38, 200, 41].into_boxed_slice(),
            }
        ).unwrap();
        debug!("encrypt output: {:?}", encrypt_out);

        let decrypt_out = session.basic_request(
            CipherOpcode::DECRYPT, //TODO: but useless, only the op in create session is used
            &mut SymCipherDataFlf::new(CipherDataFlf {
                iv_len: 0, src_data_len: 0, dst_data_len: 8, padding: 0,
            }), 
            &SymCipherDataVlfIn {
                iv: vec![0 as u8; 8].into_boxed_slice(), //len == 8 ? 
                src_data: encrypt_out.dst_data,
            }
        ).unwrap();
        debug!("decrypt output: {:?}", decrypt_out);

        session.destroy().unwrap();
        debug!("destroy end");

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