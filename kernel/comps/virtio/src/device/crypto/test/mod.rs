
use cipher::CipherTest;

use super::device::CryptoDevice;

pub mod cipher;


pub fn execute_testcases(device:& CryptoDevice){
    CipherTest::test1(device);
    CipherTest::test_aes_ecb_encrypt_decrypt(device);
    CipherTest::test_aes_cbc_encrypt_decrypt(device);
    CipherTest::test_aes_ctr_encrypt_decrypt(device);
    CipherTest::test_aes_xts_encrypt_decrypt(device);
    CipherTest::test_3des_ecb_encrypt_decrypt(device);
    CipherTest::test_3des_cbc_encrypt_decrypt(device);
    CipherTest::test_3des_ctr_encrypt_decrypt(device);

}