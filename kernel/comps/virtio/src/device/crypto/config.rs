use crate::bitflags;
use core::mem::offset_of;

use aster_util::safe_ptr::SafePtr;
use ostd::Pod;

use crate::transport::{ConfigManager, VirtioTransport};

bitflags! {
    #[repr(C)]
    #[derive(Pod)]
    pub struct FeatureBits: u64 {
        const VIRTIO_CRYPTO_F_REVISION_1              = 1 << 0;
        const VIRTIO_CRYPTO_F_CIPHER_STATELESS_MODE   = 1 << 1;
        const VIRTIO_CRYPTO_F_HASH_STATELESS_MODE     = 1 << 2;
        const VIRTIO_CRYPTO_F_MAC_STATELESS_MODE      = 1 << 3;
        const VIRTIO_CRYPTO_F_AEAD_STATELESS_MODE     = 1 << 4;
        const VIRTIO_CRYPTO_F_AKCIPHER_STATELESS_MODE = 1 << 5;
    }
}

#[derive(Debug, Pod, Clone, Copy)]
#[repr(C)]
pub struct VirtioCryptoConfig {
    pub status: u32,
    pub max_dataqueues: u32,
    pub crypto_services: u32,
    /*Detailed algorithms mask*/
    pub cipher_algo_l: u32,
    pub cipher_algo_h: u32,
    pub hash_algo: u32,
    pub mac_algo_l: u32,
    pub mac_algo_h: u32,
    pub aead_algo: u32,
    /* Maximum length of cipher key in bytes */
    pub max_cipher_key_len: u32,
    /* Maximum length of authenticated key in bytes */
    pub max_auth_key_len: u32,
    pub akcipher_algo: u32,
    /* Maximum size of each crypto request's content in bytes */
    pub max_size: u64,
}

impl VirtioCryptoConfig {
    pub(super) fn new_manager(transport: &dyn VirtioTransport) -> ConfigManager<Self> {
        let safe_ptr = transport
            .device_config_mem()
            .map(|mem| SafePtr::new(mem, 0));
        let bar_space = transport.device_config_bar();
        ConfigManager::new(safe_ptr, bar_space)
    }
}


impl ConfigManager<VirtioCryptoConfig> {
    pub(super) fn read_config(&self) -> VirtioCryptoConfig {
        let mut fs_config = VirtioCryptoConfig::new_uninit();

        macro_rules! repeat {
            ( $( $x:ident ),* ) => {
                $(
                    fs_config.$x = self
                        .read_once(offset_of!(VirtioCryptoConfig, $x))
                        .unwrap();
                )*
            };
        }
        repeat!(
            status,
            max_dataqueues,
            crypto_services,
            cipher_algo_l,
            cipher_algo_h,
            hash_algo,
            mac_algo_l,
            mac_algo_h,
            aead_algo,
            max_cipher_key_len,
            max_auth_key_len,
            akcipher_algo
        );

        let max_size_lower = self
            .read_once::<u32>(offset_of!(VirtioCryptoConfig, max_size))
            .unwrap() as u64;
        let max_size_upper = self
            .read_once::<u32>(offset_of!(VirtioCryptoConfig, max_size))
            .unwrap() as u64;
        fs_config.max_size = max_size_lower + (max_size_upper << 32);

        fs_config
    }
}