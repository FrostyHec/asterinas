
use cipher::CipherTest;

use super::device::CryptoDevice;

pub mod cipher;


pub fn execute_testcases(device:& CryptoDevice){
    CipherTest::test1(device);
    CipherTest::test2(device);
}