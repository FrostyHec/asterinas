use alloc::{boxed::Box, vec, vec::Vec};

use ostd::early_println;
use rand::Rng;

use crate::device::crypto::{device::CryptoDevice, header::*, session::*};
use rand::rngs::StdRng;
use rand::SeedableRng;
use rand::RngCore;
use alloc::string::String;
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
            &mut SymCipherCreateSessionFlf::new(CipherSessionFlf::new(algo, CryptoOp::OP_ENCRYPT)),
            &mut SymCipherCreateSessionVlf {
                cipher_key: key.as_bytes().into(), //len should be (<= ?) 24 ?
            },
        )
        .unwrap();
        let encrypt_out = encrypt_session
            .basic_request(
                CipherOpcode::ENCRYPT,
                &mut SymCipherDataFlf::new(CipherDataFlf::new(encrypted_len)),
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
            &mut SymCipherCreateSessionFlf::new(CipherSessionFlf::new(algo, CryptoOp::OP_DECRYPT)),
            &mut SymCipherCreateSessionVlf {
                cipher_key: key.as_bytes().into(), //len should be (<= ?) 24 ?
            },
        )
        .unwrap();
        let decrypt_out = decrypt_session
            .basic_request(
                CipherOpcode::DECRYPT, //TODO: but useless, only the op in create session is used
                &mut SymCipherDataFlf::new(CipherDataFlf::new(decrypted_len)),
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

    pub fn test_aes_ctr_encrypt_decrypt(device: &CryptoDevice) {
        // WARNING: orign data must be a multiple of 16,
        //          iv must be at size 16
        early_println!("Testing AES_CTR encrypt-decrypt");

        let origin_data = vec![
            190, 147, 128, 144, 239, 38, 200, 41, 190, 147, 128, 144, 239, 38, 200, 41,
        ];
        let iv = vec![1 as u8; 16]; // using iv
        let cipher_key = "yv8.,7f 0,q7fhq 1u9ep,1 ";
        let encrypted_len: u32 = origin_data.len() as u32;
        let algo = CipherAlgo::CIPHER_AES_CTR;
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
        early_println!("AES_CTR encrypt-decrypt test passed")
    }

    pub fn test_aes_xts_encrypt_decrypt(device: &CryptoDevice) {
        // WARNING: orign data must be a multiple of 16,
        //          iv must be at size 16
        //          key len must be 32
        early_println!("Testing AES_XTS encrypt-decrypt");

        let origin_data = vec![
            190, 147, 128, 144, 239, 38, 200, 41, 190, 147, 128, 144, 239, 38, 200, 41,
        ];
        let iv = vec![1 as u8; 16]; // using iv
                                    // let cipher_key = "yv8.,7f 0,q7fhq 1u9ep,1 yv8.,7f 0,q7fhq 1u9ep,1 ";
        let cipher_key = "yv8.,7f 0,q7fhq yv8.,7f 0,q7fhq ";
        let encrypted_len: u32 = origin_data.len() as u32;
        let algo = CipherAlgo::CIPHER_AES_XTS;
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
        early_println!("AES_XTS encrypt-decrypt test passed")
    }

    pub fn test_3des_ecb_encrypt_decrypt(device: &CryptoDevice) {
        // WARNING: orign data must be a multiple of 8(?),
        //          iv must be at size 8

        early_println!("Testing 3DES_ECB encrypt-decrypt");

        let origin_data = vec![190, 147, 128, 144, 239, 38, 200, 41];
        let iv = vec![1 as u8; 8]; // using iv
        let cipher_key = "yv8.,7f 0,q7fhq 1u9ep,1 ";
        let encrypted_len: u32 = origin_data.len() as u32;
        let algo = CipherAlgo::CIPHER_3DES_ECB;
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
        early_println!("3DES_ECB encrypt-decrypt test passed")
    }

    pub fn test_3des_cbc_encrypt_decrypt(device: &CryptoDevice) {
        // WARNING: orign data must be a multiple of 8(?),
        //          iv must be at size 8

        early_println!("Testing 3DES_CBC encrypt-decrypt");

        let origin_data = vec![190, 147, 128, 144, 239, 38, 200, 41];
        let iv = vec![1 as u8; 8]; // using iv
        let cipher_key = "yv8.,7f 0,q7fhq 1u9ep,1 ";
        let encrypted_len: u32 = origin_data.len() as u32;
        let algo = CipherAlgo::CIPHER_3DES_ECB;
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
        early_println!("3DES_CBC encrypt-decrypt test passed")
    }

    pub fn test_3des_ctr_encrypt_decrypt(device: &CryptoDevice) {
        // WARNING: orign data must be a multiple of 16,
        //          iv must be at size 16
        early_println!("Testing 3DES_CTR encrypt-decrypt");

        let origin_data = vec![190, 147, 128, 144, 239, 38, 200, 41];
        let iv = vec![1 as u8; 8]; // using iv
        let cipher_key = "yv8.,7f 0,q7fhq 1u9ep,1 ";
        let encrypted_len: u32 = origin_data.len() as u32;
        let algo = CipherAlgo::CIPHER_3DES_CTR;
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
        early_println!("3DES_CTR encrypt-decrypt test passed")
    }

    pub fn fuzz_testing(device: &CryptoDevice) {
        early_println!("begin Fuzz testing...");
        let mut rng = StdRng::seed_from_u64(0);
    
        let algos = [CipherAlgo::CIPHER_3DES_CTR, CipherAlgo::CIPHER_AES_CTR];
        let algo = {
            // 将 next_u64 替换为 next_u32
            let idx = (rng.next_u32() as usize) % algos.len();
            algos[idx]
        };
    
        let data_len = {
            let val = (rng.next_u32() as usize) % 128;
            (16 + val) & !0xf
        };
        let mut origin_data = vec![0_u8; data_len];
        for i in 0..origin_data.len() {
            origin_data[i] = rng.gen_range(b'a'..=b'z');
        }
    
        let iv_len = match algo {
            CipherAlgo::CIPHER_3DES_CTR => 8,
            _ => 16,
        };
        let mut iv = vec![0_u8; iv_len];
        let _ = rng.try_fill_bytes(&mut iv[..]);
    
        let key_len = match algo {
            CipherAlgo::CIPHER_AES_XTS => 32,
            _ => 24,
        };
        let mut key_buf = vec![0_u8; key_len];
        for i in 0..key_buf.len() {
            key_buf[i] = rng.gen_range(b'a'..=b'z');
        }

        let cipher_key = String::from_utf8_lossy(&key_buf);
    
        let encrypted_data = CipherTest::encrypt(
            device,
            algo,
            iv.clone(),
            &cipher_key,
            origin_data.clone(),
            origin_data.len() as u32,
        );
        let decrypted_data = CipherTest::decrypt(
            device,
            algo,
            iv,
            &cipher_key,
            encrypted_data.to_vec(),
            origin_data.len() as u32,
        );
        assert_eq!(origin_data.into_boxed_slice(), decrypted_data);
        early_println!("Fuzz testing passed!");
    }
}
