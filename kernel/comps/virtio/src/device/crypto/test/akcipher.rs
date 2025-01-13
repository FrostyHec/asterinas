use alloc::{boxed::Box, vec, vec::Vec};

use ostd::early_println;

use crate::device::crypto::{device::CryptoDevice, header::*, session::*};

pub struct AKCipherTest{}

impl AKCipherTest {
    fn encrypt_rsa(
        device: &CryptoDevice,
        key: &str,
        origin_data: Vec<u8>,
        encrypted_len: u32,
        padding_algo: RsaPaddingAlgo,
        hash_algo: RsaHashAlgo,
        key_type: AkcipherKeyType,
    ) -> Box<[u8]> {
        let mut flf = AkcipherCreateSessionFlf::new(key_type);
        flf.set_rsa(padding_algo, hash_algo);
        let encrypt_session = CryptoSession::<AkcipherSession>::new(
            &device,
            &mut flf,
            &mut AkcipherCreateSessionVlf { //len should be (<= ?) 24 ?
                key: key.as_bytes().into(),
            },
        )
        .unwrap();
        let encrypt_out = encrypt_session
            .basic_request(
                AkcipherOpcode::ENCRYPT,
                &mut AkcipherDataFlf::new(encrypted_len),
                &AkcipherDataVlfIn {
                    src_data: origin_data.into_boxed_slice(),
                },
            )
            .unwrap();
        early_println!("encrypt output: {:?}", encrypt_out);
        let encrypted_data = encrypt_out.dst_data;
        encrypt_session.destroy().unwrap();
        encrypted_data
    }

    fn decrypt_rsa(
        device: &CryptoDevice,
        key: &str,
        encrypted_data: Vec<u8>,
        decrypted_len: u32,
        padding_algo: RsaPaddingAlgo,
        hash_algo: RsaHashAlgo,
        key_type: AkcipherKeyType,
    ) -> Box<[u8]> {
        let mut flf = AkcipherCreateSessionFlf::new(key_type);
        flf.set_rsa(padding_algo, hash_algo);
        let decrypt_session = CryptoSession::<AkcipherSession>::new(
            &device,
            &mut flf,
            &mut AkcipherCreateSessionVlf {
                key: key.as_bytes().into(),
            },
        )
        .unwrap();
        let decrypt_out = decrypt_session
            .basic_request(
                AkcipherOpcode::DECRYPT,
                &mut AkcipherDataFlf::new(decrypted_len),
                &AkcipherDataVlfIn {
                    src_data: encrypted_data.into_boxed_slice(),
                },
            )
            .unwrap();
        early_println!("decrypt output: {:?}", decrypt_out);
        let decrypted_data = decrypt_out.dst_data;
        decrypt_session.destroy().unwrap();
        decrypted_data
    }

    pub fn test1(device: &CryptoDevice) {
        early_println!("testcase1 from akcipherTest!");
    }

    pub fn test_rsa_encrypt_decrypt(device: &CryptoDevice) {
        let key = "yv8.,7f 0,q7fhq 1u9ep,1 ";
        let origin_data = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let encrypted_data = Self::encrypt_rsa(
            device,
            key,
            origin_data.clone(),
            128,
            RsaPaddingAlgo::RSA_PKCS1_PADDING,
            RsaHashAlgo::RSA_MD2,
            AkcipherKeyType::AKCIPHER_KEY_TYPE_PUBLIC,
        );
        let decrypted_data = Self::decrypt_rsa(
            device,
            key,
            encrypted_data.to_vec(),
            8,
            RsaPaddingAlgo::RSA_PKCS1_PADDING,
            RsaHashAlgo::RSA_MD2,
            AkcipherKeyType::AKCIPHER_KEY_TYPE_PUBLIC,
        );
        assert_eq!(origin_data, decrypted_data.to_vec());
        early_println!("test_rsa_encrypt_decrypt passed!");
    }

    
}