use alloc::{
    boxed::Box,
    collections::btree_map::BTreeMap,
    rc::Rc,
    string::{String, ToString},
    sync::Arc,
    vec,
};
use core::{cmp, hint::spin_loop, iter::Map};

use aster_bigtcp::device;
use aster_crypto::{
    args_const::{self, service},
    register_device, VirtIOCryptoDevice,
};
use log::debug;
use ostd::{
    early_println,
    mm::{DmaDirection, DmaStream, DmaStreamSlice, FrameAllocOptions, VmReader, PAGE_SIZE},
    sync::SpinLock,
};
use session::{CryptoSession, CryptoSessionEnum, SymCipherSession};

use super::config::{FeatureBits, VirtioCryptoConfig};
use crate::{
    device::{
        crypto::{header::*, test::execute_testcases, *},
        VirtioDeviceError,
    },
    queue::VirtQueue,
    transport::{ConfigManager, VirtioTransport},
};

fn bytes_into_dma(bytes: &[u8], init: bool) -> DmaStreamSlice<DmaStream> {
    let vm_segment = FrameAllocOptions::new((bytes.len() - 1) / PAGE_SIZE + 1)
        .alloc_contiguous()
        .unwrap();
    let stream = DmaStream::map(vm_segment, DmaDirection::Bidirectional, false).unwrap();
    if init {
        let mut writer = stream.writer().unwrap();
        writer.write(&mut VmReader::from(bytes));
    }
    DmaStreamSlice::new(stream, 0, bytes.len())
}
#[derive(Debug)]
pub struct CryptoService {
    device: Arc<CryptoDevice>,
    session_map: SpinLock<BTreeMap<u64, CryptoSessionEnum>>,
}

#[derive(Debug)]
pub struct CryptoDevice {
    config_manager: ConfigManager<VirtioCryptoConfig>,
    transport: SpinLock<Box<dyn VirtioTransport>>,

    pub data_queue: SpinLock<VirtQueue>,
    pub control_queue: SpinLock<VirtQueue>,

    pub features: FeatureBits,
}
fn get_or_return<'a>(
    map: &'a BTreeMap<String, String>,
    key: &str,
) -> Result<&'a String, &'static str> {
    map.get(key).ok_or_else(|| {
        early_println!("{:?} Not Found", key);
        "Key Not Found"
    })
}
impl VirtIOCryptoDevice for CryptoService {
    // some are not support for user layer since qemu not support
    fn create_sesson(&self, args: BTreeMap<String, String>) -> Result<u64, &str> {
        let service = get_or_return(&args, args_const::service::FIELD_NAME)?;
        let key = get_or_return(&args, args_const::KEY_FIELD_NAME)?;
        let session_op_name = get_or_return(&args, args_const::session_op::FIELD_NAME)?;
        let session_op = match session_op_name.as_str() {
            args_const::session_op::ENCRYPT_NAME => CryptoOp::OP_ENCRYPT,
            args_const::session_op::DECRYPT_NAME => CryptoOp::OP_DECRYPT,
            _ => {
                early_println!("Unsupported session-op name {:?}", session_op_name);
                return Err("Unsupported session-op name");
            }
        };
        match service.as_str() {
            args_const::service::SYM_CIPHER_NAME => {
                let algo_name = get_or_return(&args, args_const::ALGO_FIELD_NAME)?;
                let algo = match algo_name.as_str() {
                    args_const::algo::cipher::AES_ECB => CipherAlgo::CIPHER_AES_ECB,
                    _ => {
                        early_println!("Unsupported algo name {:?}", algo_name);
                        return Err("Unsupported algo name");
                    }
                };
                let session = CryptoSession::<SymCipherSession>::new(
                    self.device.clone(),
                    &mut SymCipherCreateSessionFlf::new(CipherSessionFlf::new(algo, session_op)),
                    &mut SymCipherCreateSessionVlf {
                        cipher_key: key.as_bytes().into(), //len should be (<= ?) 24 ?
                    },
                )
                .unwrap();
                let session_id = session.session_id;
                self.session_map
                    .lock()
                    .insert(session_id, CryptoSessionEnum::SymCipher(session));
                Ok(session_id)
            }
            _ => {
                early_println!("Unsupport Service type {:?}", service.as_str());
                Err("Unsupport Service type")
            }
        }
    }
    fn destroy_session(&self, args: BTreeMap<String, String>) -> Result<(), &str> {
        let session_id_str = get_or_return(&args, args_const::SESSION_ID_FIELD_NAME)?;
        let session_id: u64 = match session_id_str.parse::<u64>() {
            Ok(id) => id,
            Err(_) => {
                early_println!("Failed to parse session-id: {:?}", session_id_str);
                return Err("Invalid session-id format");
            }
        };
        match self.session_map.lock().get(&session_id) {
            Some(session) => {
                let _ = match session {
                    CryptoSessionEnum::Hash(crypto_session) => crypto_session.destroy(),
                    CryptoSessionEnum::Mac(crypto_session) => crypto_session.destroy(),
                    CryptoSessionEnum::SymCipher(crypto_session) => crypto_session.destroy(),
                    CryptoSessionEnum::SymAlgChain(crypto_session) => crypto_session.destroy(),
                    CryptoSessionEnum::Aead(crypto_session) => crypto_session.destroy(),
                    CryptoSessionEnum::Akcipher(crypto_session) => crypto_session.destroy(),
                };
                Ok(())
            }
            None => {
                early_println!("Session Not Found: {:?}", session_id);
                return Err("Session Not Found");
            }
        }
    }

    fn stateful_operation(&self, args: BTreeMap<String, String>)->Result<Box<[u8]>,&str> {
        let session_id_str = get_or_return(&args, args_const::SESSION_ID_FIELD_NAME)?;
        let session_id: u64 = match session_id_str.parse::<u64>() {
            Ok(id) => id,
            Err(_) => {
                early_println!("Failed to parse session-id: {:?}", session_id_str);
                return Err("Invalid session-id format");
            }
        };
        let iv = get_or_return(&args, args_const::IV_FIELD_NAME)?;
        let src_data = get_or_return(&args, args_const::SRC_FIELD_NAME)?;
        let out_len_str = get_or_return(&args, args_const::OUT_LEN_NAME)?;
        let out_len: u32 = match out_len_str.parse::<u32>() {
            Ok(id) => id,
            Err(_) => {
                early_println!("Failed to parse out-len: {:?}", out_len_str);
                return Err("Invalid out-len format");
            }
        };
        match self.session_map.lock().get(&session_id) {
            Some(session) => {
                let encrypt_out = match session {
                    CryptoSessionEnum::SymCipher(crypto_session) => {
                        let res = crypto_session
                            .basic_request(
                                CipherOpcode::ENCRYPT,
                                &mut SymCipherDataFlf::new(CipherDataFlf::new(out_len)),
                                &SymCipherDataVlfIn {
                                    iv: iv.as_bytes().into(), 
                                    src_data: src_data.as_bytes().into(),
                                },
                            );
                        match res {
                            Ok(value)=> value,
                            Err(e) => {
                                early_println!("Failed Response Status {:?}",e);
                                return Err("Failed Response Status");
                            },
                        }    
                    }
                    _ => {
                        early_println!("Session type not support: {:?}", session_id);
                        return Err("Session type not support");
                    }
                };
                Ok(encrypt_out.dst_data.clone())
            }
            None => {
                early_println!("Session Not Found: {:?}", session_id);
                return Err("Session Not Found");
            }
        }
    }
    
    fn stateless_operation(&self, args: BTreeMap<String, String>)->Result<Box<[u8]>,&str> {
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
        let data_queue = SpinLock::new(VirtQueue::new(0, QUEUE_SIZE, transport.as_mut()).unwrap());
        let control_queue = SpinLock::new(
            VirtQueue::new(config.max_dataqueues as u16, QUEUE_SIZE, transport.as_mut()).unwrap(),
        );

        let device = CryptoDevice {
            config_manager,
            transport: SpinLock::new(transport),
            data_queue,
            control_queue,
            features: FeatureBits::empty(),
        };
        device.transport.lock().finish_init();

        let service = CryptoService {
            device: Arc::new(device),
            session_map: SpinLock::new(BTreeMap::new()),
        };

        execute_testcases(service.device.clone());
        register_device(args_const::device::DEFAULT_NAME, Arc::new(service));

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
