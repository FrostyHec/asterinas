use alloc::vec;
use ostd::early_println;

use crate::device::crypto::{device::CryptoDevice, header::*, session::*};

pub struct CipherTest {}

impl CipherTest {
    pub fn test1(device: &CryptoDevice) {
        early_println!("hello testcase1!");
    }

    pub fn test2(device: &CryptoDevice) {
        early_println!("hello testcase2!");

        let session = CryptoSession::<SymCipherSession>::new(
            &device,
            &mut SymCipherCreateSessionFlf::new(CipherSessionFlf::new(
                CipherAlgo::CIPHER_3DES_CBC,
                0, //auto filled
                CryptoOp::OP_DECRYPT,
            )),
            &mut SymCipherCreateSessionVlf {
                cipher_key: "yv8.,7f 0,q7fhq 1u9ep,1 ".as_bytes().into(), //len should be (<= ?) 24 ?
            },
        )
        .unwrap();
        early_println!("create end");

        let encrypt_out = session
            .basic_request(
                DataOpcode::CIPHER_ENCRYPT as u32, //TODO
                &mut SymCipherDataFlf::new(CipherDataFlf {
                    iv_len: 0,
                    src_data_len: 0,
                    dst_data_len: 8,
                    padding: 0,
                }),
                &SymCipherDataVlfIn {
                    iv: vec![0 as u8; 8].into_boxed_slice(), //len == 8 ?
                    src_data: vec![190, 147, 128, 144, 239, 38, 200, 41].into_boxed_slice(),
                },
            )
            .unwrap();
        early_println!("encrypt output: {:?}", encrypt_out);

        let decrypt_out = session
            .basic_request(
                DataOpcode::CIPHER_DECRYPT as u32, //TODO: but useless, only the op in create session is used
                &mut SymCipherDataFlf::new(CipherDataFlf {
                    iv_len: 0,
                    src_data_len: 0,
                    dst_data_len: 8,
                    padding: 0,
                }),
                &SymCipherDataVlfIn {
                    iv: vec![0 as u8; 8].into_boxed_slice(), //len == 8 ?
                    src_data: encrypt_out.dst_data,
                },
            )
            .unwrap();
        early_println!("decrypt output: {:?}", decrypt_out);

        session.destroy().unwrap();
        early_println!("destroy end");
    }
}
