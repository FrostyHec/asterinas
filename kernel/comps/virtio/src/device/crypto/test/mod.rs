
use alloc::sync::Arc;
use cipher::CipherTest;

use super::device::CryptoDevice;

pub mod cipher;


pub fn execute_testcases(device:Arc<CryptoDevice>){
    CipherTest::test_aes_ecb_encrypt_decrypt(device.clone());
    CipherTest::test_aes_cbc_encrypt_decrypt(device.clone());
    CipherTest::test_aes_ctr_encrypt_decrypt(device.clone());
    CipherTest::test_aes_xts_encrypt_decrypt(device.clone());
    CipherTest::test_3des_ecb_encrypt_decrypt(device.clone());
    CipherTest::test_3des_cbc_encrypt_decrypt(device.clone());
    CipherTest::test_3des_ctr_encrypt_decrypt(device.clone());
}