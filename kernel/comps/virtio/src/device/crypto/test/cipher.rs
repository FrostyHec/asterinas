use alloc::{boxed::Box, vec, vec::Vec};

use ostd::early_println;

use crate::device::crypto::{device::CryptoDevice, header::*, session::*};

pub struct CipherTest {}

impl CipherTest {
    fn encrypt(
        device: &CryptoDevice,
        algo: CipherAlgo,
        iv: Vec<u8>,
        key: &str,
        origin_data: Vec<u8>,
        encrypted_len: u32,
    ) -> Box<[u8]> {
        let encrypt_session = CryptoSession::<SymCipherSession>::new(
            &device,
            &mut SymCipherCreateSessionFlf::new(CipherSessionFlf::new(
                algo,
                0, //auto filled
                CryptoOp::OP_ENCRYPT,
            )),
            &mut SymCipherCreateSessionVlf {
                cipher_key: key.as_bytes().into(), //len should be (<= ?) 24 ?
            },
        )
        .unwrap();
        let encrypt_out = encrypt_session
            .basic_request(
                DataOpcode::CIPHER_ENCRYPT as u32,
                &mut SymCipherDataFlf::new(CipherDataFlf {
                    iv_len: 0,
                    src_data_len: 0,
                    dst_data_len: encrypted_len,
                    padding: 0,
                }),
                &SymCipherDataVlfIn {
                    iv: iv.into_boxed_slice(), //len == 8 ?
                    src_data: origin_data.into_boxed_slice(),
                },
            )
            .unwrap();
        early_println!("encrypt output: {:?}", encrypt_out);
        let encrypted_data = encrypt_out.dst_data;
        encrypt_session.destroy().unwrap();
        encrypted_data
    }

    fn decrypt(
        device: &CryptoDevice,
        algo: CipherAlgo,
        iv: Vec<u8>,
        key: &str,
        origin_data: Vec<u8>,
        decrypted_len: u32,
    ) -> Box<[u8]> {
        let decrypt_session = CryptoSession::<SymCipherSession>::new(
            &device,
            &mut SymCipherCreateSessionFlf::new(CipherSessionFlf::new(
                algo,
                0, //auto filled
                CryptoOp::OP_DECRYPT,
            )),
            &mut SymCipherCreateSessionVlf {
                cipher_key: key.as_bytes().into(), //len should be (<= ?) 24 ?
            },
        )
        .unwrap();
        let decrypt_out = decrypt_session
            .basic_request(
                DataOpcode::CIPHER_DECRYPT as u32, //TODO: but useless, only the op in create session is used
                &mut SymCipherDataFlf::new(CipherDataFlf {
                    iv_len: 0,
                    src_data_len: 0,
                    dst_data_len: decrypted_len,
                    padding: 0,
                }),
                &SymCipherDataVlfIn {
                    iv: iv.into_boxed_slice(), //len == 8 ?
                    src_data: origin_data.into_boxed_slice(),
                },
            )
            .unwrap();
        early_println!("decrypt output: {:?}", decrypt_out);
        let decrypted_data = decrypt_out.dst_data;
        decrypt_session.destroy().unwrap();
        decrypted_data
    }

    pub fn test1(device: &CryptoDevice) {
        early_println!("hello testcase1!");
    }

    pub fn test_aes_ecb_encrypt_decrypt(device: &CryptoDevice) {
        // WARNING: orign data must be a multiple of 16,
        //          iv must be at size 16
        early_println!("Testing AES_ECB encrypt-decrypt");

        let origin_data = vec![
            190, 147, 128, 144, 239, 38, 200, 41, 190, 147, 128, 144, 239, 38, 200, 41,
        ];
        let iv = vec![0 as u8; 16];
        let cipher_key = "yv8.,7f 0,q7fhq 1u9ep,1 ";
        let encrypted_len: u32 = origin_data.len() as u32;
        let algo = CipherAlgo::CIPHER_AES_ECB;
        // encrypt
        early_println!("encrypting: {:?}", origin_data);
        let encryped_data = CipherTest::encrypt(
            device,
            algo,
            iv.clone(),
            &cipher_key,
            origin_data.clone(),
            encrypted_len,
        );
        // decrypt
        let decrypted_data = CipherTest::decrypt(
            device,
            algo,
            iv,
            &cipher_key,
            encryped_data.to_vec(),
            origin_data.len() as u32,
        );

        assert_eq!(origin_data, decrypted_data.to_vec());
        early_println!("AES_ECB encrypt-decrypt test passed")
    }

    pub fn test_aes_cbc_encrypt_decrypt(device: &CryptoDevice) {
        // WARNING: orign data must be a multiple of 16,
        //          iv must be at size 16
        early_println!("Testing AES_CBC encrypt-decrypt");

        let origin_data = vec![
            190, 147, 128, 144, 239, 38, 200, 41, 190, 147, 128, 144, 239, 38, 200, 41,
        ];
        let iv = vec![1 as u8; 16]; // using iv
        let cipher_key = "yv8.,7f 0,q7fhq 1u9ep,1 ";
        let encrypted_len: u32 = origin_data.len() as u32;
        let algo = CipherAlgo::CIPHER_AES_CBC;
        // encrypt
        early_println!("encrypting: {:?}", origin_data);
        let encryped_data = CipherTest::encrypt(
            device,
            algo,
            iv.clone(),
            &cipher_key,
            origin_data.clone(),
            encrypted_len,
        );
        // decrypt
        let decrypted_data = CipherTest::decrypt(
            device,
            algo,
            iv,
            &cipher_key,
            encryped_data.to_vec(),
            origin_data.len() as u32,
        );
        assert_eq!(origin_data.into_boxed_slice(), decrypted_data);
        early_println!("AES_CBC encrypt-decrypt test passed")
    }
}
