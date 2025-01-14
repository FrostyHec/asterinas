use bitflags::bitflags;
use alloc::boxed::Box;
use int_to_c_enum::TryFromInt;
use ostd::Pod;


#[repr(u32)]
#[derive(Clone, Copy)]
#[allow(non_camel_case_types)]
pub enum ServiceCode {
    ///CIPHER (Symmetric Key Cipher) service
    CIPHER = 0,
    ///HASH service
    HASH = 1,
    ///MAC (Message Authentication Codes) service
    MAC = 2,
    ///AEAD (Authenticated Encryption with Associated Data) service
    AEAD = 3,
    ///AKCIPHER (Asymmetric Key Cipher) service
    AKCIPHER = 4,
}

#[derive(Clone, Copy)]
#[allow(non_camel_case_types)]
pub enum CipherAlgo {
    NO_CIPHER = 0,
    CIPHER_ARC4 = 1,
    CIPHER_AES_ECB = 2,
    CIPHER_AES_CBC = 3,
    CIPHER_AES_CTR = 4,
    CIPHER_DES_ECB = 5,
    CIPHER_DES_CBC = 6,
    CIPHER_3DES_ECB = 7,
    CIPHER_3DES_CBC = 8,
    CIPHER_3DES_CTR = 9,
    CIPHER_KASUMI_F8 = 10,
    CIPHER_SNOW3G_UEA2 = 11,
    CIPHER_AES_F8 = 12,
    CIPHER_AES_XTS = 13,
    CIPHER_ZUC_EEA3 = 14,
}
#[derive(Clone, Copy)]
#[allow(non_camel_case_types)]
pub enum HashAlgo {
    NO_HASH = 0,
    HASH_MD5 = 1,
    HASH_SHA1 = 2,
    HASH_SHA_224 = 3,
    HASH_SHA_256 = 4,
    HASH_SHA_384 = 5,
    HASH_SHA_512 = 6,
    HASH_SHA3_224 = 7,
    HASH_SHA3_256 = 8,
    HASH_SHA3_384 = 9,
    HASH_SHA3_512 = 10,
    HASH_SHA3_SHAKE128 = 11,
    HASH_SHA3_SHAKE256 = 12,
}
#[derive(Clone, Copy)]
#[allow(non_camel_case_types)]
pub enum MacAlgo {
    NO_MAC = 0,
    MAC_HMAC_MD5 = 1,
    MAC_HMAC_SHA1 = 2,
    MAC_HMAC_SHA_224 = 3,
    MAC_HMAC_SHA_256 = 4,
    MAC_HMAC_SHA_384 = 5,
    MAC_HMAC_SHA_512 = 6,
    MAC_CMAC_3DES = 25,
    MAC_CMAC_AES = 26,
    MAC_KASUMI_F9 = 27,
    MAC_SNOW3G_UIA2 = 28,
    MAC_GMAC_AES = 41,
    MAC_GMAC_TWOFISH = 42,
    MAC_CBCMAC_AES = 49,
    MAC_CBCMAC_KASUMI_F9 = 50,
    MAC_XCBC_AES = 53,
    MAC_ZUC_EIA3 = 54,
}
#[derive(Clone, Copy)]
#[allow(non_camel_case_types)]
pub enum AeadAlgo {
    NO_AEAD = 0,
    AEAD_GCM = 1,
    AEAD_CCM = 2,
    AEAD_CHACHA20_POLY1305 = 3,
}
#[derive(Clone, Copy)]
#[allow(non_camel_case_types)]
pub enum AkcipherAlgo {
    NO_AKCIPHER = 0,
    AKCIPHER_RSA = 1,
    AKCIPHER_ECDSA = 2,
}
#[derive(Clone, Copy)]
#[repr(u8)]
#[derive(Debug, TryFromInt)]
#[allow(non_camel_case_types)]
pub enum Status {
    OK = 0,
    ERR = 1,
    BADMSG = 2,
    NOTSUPP = 3,
    INVSESS = 4,
    NOSPC = 5,
    KEY_REJECTED = 6,
    MAX = 7,
}


/// A trait that implimented automatically by the macro `variable_length_fields!{}`.
/// 
/// The struct that impliment this trait typically contains `Box<[u8]>` field(s) that each repesents a variable length field.
/// 
/// The length of the field is binding with the field in another struct by the macro `variable_length_fields!{}`.
pub trait VarLenFields<T> {
    /// Generate a `VarLenFields`, whose lengths is specif
    fn from_bytes(bytes: &[u8], packet: &T) -> Self;
    /// Filled the binded fields of T automatically
    fn fill_lengths(&self, packet: &mut T);
    /// sum of the `Box<[u8]>` fields' lengths
    fn len(&self) -> usize;
    /// sum of the binding lengths in the T
    fn len_from_packet(packet: &T) -> usize;
    /// Iterate over all the `Box<[u8]>` fields and apply each of it with the function `func`
    fn iter_over(&self, func: impl FnMut(&Box<[u8]>));
}

/** A macro that create a VarLenFields according the struct which contains the fields that specific the length.

### Example
 
```
struct Len {
    pub len: u32,
    pub other: u16,
}
variable_length_fields! {
    struct Vlf <= Len {
        pub field: [u8; len], 
    }
}

let vlf = Vlf { field: b"happy".as_slice().into() };
let mut l = Len { len: 0, other: 123 };
vlf.fill_lengths(l);
assert_eq!(l.len, 5);
```
*/
macro_rules! variable_length_fields {
    (
        $(#[$outer:meta])*
        $vis:vis struct $StructName:ident <= $T:ty {
            $(
                $(#[$inner:ident $($args:tt)*])*
                $fvis:vis $field:ident: [u8; $($len:ident),+],
            )*
        }
        $(#[$impl_outer:meta])*
    ) => {
        $(#[$outer])*
        $vis struct $StructName {
            $(
                $fvis $field: Box<[u8]>,
            )*
        }

        $(#[$impl_outer])*
        impl VarLenFields<$T> for $StructName {
            #[allow(unused_assignments)]
            fn from_bytes(bytes: &[u8], packet: &$T) -> Self {
                let mut begin: usize = 0;
                $(
                    let len = packet$( .$len )+ as usize;
                    let $field = bytes[begin..begin+len].into();
                    begin += len;
                )*
                $StructName {
                    $( $field, )*
                }
            }
            
            fn fill_lengths(&self, packet: &mut $T) {
                $(
                    packet$( .$len )+ = self.$field.len() as u32;
                )*
            }

            fn len(&self) -> usize {
                0 $( + self.$field.len() )*
            }

            fn len_from_packet(packet: &$T) -> usize {
                0 $( + (packet$( .$len )+ as usize) )*
            }

            fn iter_over(&self, mut func: impl FnMut(&Box<[u8]>)) {
                $( func(&self.$field); )*
            }
        }

    }
}

const fn opcode(service: ServiceCode, op: u32) -> u32 {
    ((service as u32) << 8) | op
}

//
//  Control Virtqueue
//

#[repr(u32)]
#[allow(non_camel_case_types)]
pub enum ControlOpcode {
    CIPHER_CREATE_SESSION =
        opcode(ServiceCode::CIPHER, 0x02),
    CIPHER_DESTROY_SESSION =
        opcode(ServiceCode::CIPHER, 0x03),
    HASH_CREATE_SESSION =
        opcode(ServiceCode::HASH, 0x02),
    HASH_DESTROY_SESSION =
        opcode(ServiceCode::HASH, 0x03),
    MAC_CREATE_SESSION =
        opcode(ServiceCode::MAC, 0x02),
    MAC_DESTROY_SESSION =
        opcode(ServiceCode::MAC, 0x03),
    AEAD_CREATE_SESSION =
        opcode(ServiceCode::AEAD, 0x02),
    AEAD_DESTROY_SESSION =
        opcode(ServiceCode::AEAD, 0x03),
    AKCIPHER_CREATE_SESSION =
        opcode(ServiceCode::AKCIPHER, 0x04),
    AKCIPHER_DESTROY_SESSION =
        opcode(ServiceCode::AKCIPHER, 0x05),
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct ControlHeader {
    pub opcode: u32, //pub enum ControlOpcode
    /// algo should be service-specific algorithms  
    pub algo: u32,
    pub flag: u32,
    pub reserved: u32,
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct CreateSessionInput { 
    pub session_id: u64, 
    pub status: u32, 
    pub padding: u32, 
}
impl CreateSessionInput {
    pub fn get_status(&self) -> Status {
        TryInto::<Status>::try_into(self.status as u8).unwrap_or(Status::MAX) // TODO: unsafe as u8
    } 
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct DestroySessionFlf { 
    /// Device read only portion  
    pub session_id: u64, 
}
 
#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct DestroySessionInput { 
    /// Device write only portion  
    pub status: u8, 
}
impl DestroySessionInput {
    pub fn get_status(&self) -> Status {
        TryInto::<Status>::try_into(self.status).unwrap_or(Status::MAX)
    } 
}

pub trait CtrlFixedLenFields {
    fn get_algo(&self) -> u32;
}

pub trait ControlFlf: Sized + Pod + Default + CtrlFixedLenFields {
    type Vlf: VarLenFields<Self>;
    const CREATE_SESSION:  ControlOpcode;
    const DESTROY_SESSION: ControlOpcode;
}

impl ControlFlf for HashCreateSessionFlf {
    type Vlf = HashNoVlf;
    const CREATE_SESSION:  ControlOpcode = ControlOpcode::HASH_CREATE_SESSION;
    const DESTROY_SESSION: ControlOpcode = ControlOpcode::HASH_DESTROY_SESSION;
}

impl ControlFlf for MacCreateSessionFlf {
    type Vlf = MacCreateSessionVlf;
    const CREATE_SESSION:  ControlOpcode = ControlOpcode::MAC_CREATE_SESSION;
    const DESTROY_SESSION: ControlOpcode = ControlOpcode::MAC_DESTROY_SESSION;
}

impl ControlFlf for SymCipherCreateSessionFlf {
    type Vlf = SymCipherCreateSessionVlf;
    const CREATE_SESSION:  ControlOpcode = ControlOpcode::CIPHER_CREATE_SESSION;
    const DESTROY_SESSION: ControlOpcode = ControlOpcode::CIPHER_DESTROY_SESSION;
}

impl ControlFlf for SymAlgChainCreateSessionFlf {
    type Vlf = SymAlgChainCreateSessionVlf;
    const CREATE_SESSION:  ControlOpcode = ControlOpcode::CIPHER_CREATE_SESSION;
    const DESTROY_SESSION: ControlOpcode = ControlOpcode::CIPHER_DESTROY_SESSION;
}

impl ControlFlf for AeadCreateSessionFlf {
    type Vlf = AeadCreateSessionVlf;
    const CREATE_SESSION:  ControlOpcode = ControlOpcode::AEAD_CREATE_SESSION;
    const DESTROY_SESSION: ControlOpcode = ControlOpcode::AEAD_DESTROY_SESSION;
}

impl ControlFlf for AkcipherCreateSessionFlf {
    type Vlf = AkcipherCreateSessionVlf;
    const CREATE_SESSION:  ControlOpcode = ControlOpcode::AKCIPHER_CREATE_SESSION;
    const DESTROY_SESSION: ControlOpcode = ControlOpcode::AKCIPHER_DESTROY_SESSION;
}


#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct HashCreateSessionFlf { 
    /// Device read only portion  

    /// See HASH_* above 
    algo: u32,
    /// hash result length  
    pub hash_result_len: u32, 
}
impl HashCreateSessionFlf {
    pub fn new(algo: HashAlgo, hash_result_len: u32) -> Self {
        Self {
            algo: algo as u32,
            hash_result_len,
        }
    }
}
impl CtrlFixedLenFields for HashCreateSessionFlf {
    fn get_algo(&self) -> u32 {
        self.algo
    }
}

variable_length_fields! {
    #[derive(Default, Debug, Clone)]
    pub struct HashNoVlf <= HashCreateSessionFlf {}
    #[allow(unused_variables, unused_mut)]
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct MacCreateSessionFlf { 
    /// Device read only portion  
 
    /// See MAC_* above  
    algo: u32, 
    /// hash result length  
    pub hash_result_len: u32, 
    /// length of authenticated key  
    auth_key_len: u32, 
    pub padding: u32, 
}
impl MacCreateSessionFlf {
    pub fn new(algo: MacAlgo, hash_result_len: u32) -> Self {
        Self {
            algo: algo as u32,
            hash_result_len,
            auth_key_len: 0, // Auto filled
            padding: 0,
        }
    }
}
impl CtrlFixedLenFields for MacCreateSessionFlf {
    fn get_algo(&self) -> u32 {
        self.algo
    }
}

variable_length_fields! {
    #[derive(Default, Debug, Clone)]
    pub struct MacCreateSessionVlf <= MacCreateSessionFlf { 
        /// Device read only portion  
     
        /// The authenticated key  
        pub auth_key: [u8; auth_key_len], 
    }
}

#[allow(non_camel_case_types)]
pub enum SymOp {
    /// No operation  
    SYM_OP_NONE = 0, 
    /// Cipher only operation on the data  
    SYM_OP_CIPHER = 1, 
    /* Chain any cipher with any hash or mac operation. The order 
    depends on the value of alg_chain_order param */ 
    SYM_OP_ALGORITHM_CHAINING = 2, 
}

#[allow(non_camel_case_types)]
pub enum CryptoOp {
    OP_ENCRYPT = 1, 
    OP_DECRYPT = 2, 
}


#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct CipherPara {
    /// See CIPHER* above  
    algo: u32, 
    /// length of key  
    key_len: u32, 

    /// encryption or decryption  
    op: u32, //pub enum CRYPTO_OP
}
impl CipherPara {
    pub fn new(algo: CipherAlgo, op: CryptoOp) -> Self {
        Self {
            algo: algo as u32,
            key_len: 0, // Auto filled
            op: op as u32,
        }
    }
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct CipherSessionFlf { 
    /// Device read only portion  
    pub para: CipherPara,
    pub padding: u32, 
}
impl CipherSessionFlf {
    pub fn new(algo: CipherAlgo, op: CryptoOp) -> Self {
        Self {
            para: CipherPara::new(algo, op),
            padding: 0,
        }
    }
}
const CIPHER_SESSION_FLF_PADDING_SIZE: usize = SYM_SESS_OP_SPEC_HDR_SIZE - size_of::<CipherSessionFlf>();

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct SymCipherCreateSessionFlf {
    pub op_flf: CipherSessionFlf,
    padding_bytes: [u8; CIPHER_SESSION_FLF_PADDING_SIZE],

    op_type: u32, //pub enum sym_op
    padding: u32, 
}
impl SymCipherCreateSessionFlf {
    pub fn new(op_flf: CipherSessionFlf) -> Self {
        Self {
            op_flf,
            padding_bytes: [0; CIPHER_SESSION_FLF_PADDING_SIZE],
            op_type: SymOp::SYM_OP_CIPHER as u32,
            padding: 0,
        }
    }
}
impl CtrlFixedLenFields for SymCipherCreateSessionFlf {
    fn get_algo(&self) -> u32 {
        self.op_flf.para.algo
    }
}

variable_length_fields! {
    #[derive(Default, Debug, Clone)]
    pub struct SymCipherCreateSessionVlf <= SymCipherCreateSessionFlf { 
        /// Device read only portion  
    
        /// The cipher key  
        pub cipher_key: [u8; op_flf, para, key_len], 
    }
}

#[allow(non_camel_case_types)]
pub enum AlgChainOrder {
    SYM_ALG_CHAIN_ORDER_HASH_THEN_CIPHER = 1, 
    SYM_ALG_CHAIN_ORDER_CIPHER_THEN_HASH = 2, 
}

#[allow(non_camel_case_types)]
pub enum SymHashMode {
    /// Plain hash  
    SYM_HASH_MODE_PLAIN = 1, 
    /// Authenticated hash (mac)  
    SYM_HASH_MODE_AUTH = 2, 
    /// Nested hash  
    SYM_HASH_MODE_NESTED = 3, 
}

const ALG_CHAIN_SESS_OP_SPEC_HDR_SIZE: usize = 16; 

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct AlgChainAlgoFlf {
    /// Device read only portion  
 
    /// See MAC_* or HASH_* above  
    pub algo: u32, 
    /// hash result length  
    pub hash_result_len: u32, 
    /// length of authenticated key  
    pub auth_key_len: u32, 
    pub padding: u32, 
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct AlgChainSessionFlf { 
    /// Device read only portion  

    alg_chain_order: u32, //pub enum alg_chain_order

    hash_mode: u32, //pub enum sym_hash_mode
    pub cipher_hdr: CipherSessionFlf,
 
    /// fixed length fields, algo specific  
    // pub algo_flf: [u8; VIRTIO_CRYPTO_ALG_CHAIN_SESS_OP_SPEC_HDR_SIZE],
    algo_flf: AlgChainAlgoFlf, 
 
    /// length of the additional authenticated data (AAD) in bytes  
    pub aad_len: u32, 
    padding: u32,
}
impl AlgChainSessionFlf {
    pub fn new(alg_chain_order: AlgChainOrder, cipher_hdr: CipherSessionFlf, aad_len: u32) -> Self {
        Self {
            alg_chain_order: alg_chain_order as u32,
            hash_mode: SymHashMode::SYM_HASH_MODE_PLAIN as u32,
            cipher_hdr,
            algo_flf: AlgChainAlgoFlf {
                algo: 0, hash_result_len: 0, auth_key_len: 0, padding: 0,
            },
            aad_len,
            padding: 0,
        }
    }
    pub fn set_hash(mut self, algo: HashAlgo, hash_result_len: u32) -> Self {
        self.hash_mode = SymHashMode::SYM_HASH_MODE_NESTED as u32;
        self.algo_flf.algo = algo as u32;
        self.algo_flf.hash_result_len = hash_result_len;
        self.algo_flf.auth_key_len = 0;
        self
    }
    pub fn set_mac(mut self, algo: MacAlgo, hash_result_len: u32) -> Self {
        self.hash_mode = SymHashMode::SYM_HASH_MODE_AUTH as u32;
        self.algo_flf.algo = algo as u32;
        self.algo_flf.hash_result_len = hash_result_len;
        self.algo_flf.auth_key_len = 0; // Auto filled
        self
    }
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct SymAlgChainCreateSessionFlf {
    pub op_flf: AlgChainSessionFlf,

    op_type: u32, //pub enum sym_op
    padding: u32, 
}
impl SymAlgChainCreateSessionFlf {
    pub fn new(op_flf: AlgChainSessionFlf) -> Self {
        Self {
            op_flf,
            op_type: SymOp::SYM_OP_ALGORITHM_CHAINING as u32,
            padding: 0, 
        }
    }
}
impl CtrlFixedLenFields for SymAlgChainCreateSessionFlf {
    fn get_algo(&self) -> u32 {
        self.op_flf.cipher_hdr.para.algo
    }
}

variable_length_fields!{
    pub struct SymAlgChainCreateSessionVlf <= SymAlgChainCreateSessionFlf { 
        /// Device read only portion  
    
        /// The cipher key  
        pub cipher_key: [u8; op_flf, cipher_hdr, para, key_len], 
        /// The authenticated key  
        pub auth_key: [u8; op_flf, algo_flf, auth_key_len], 
    }
}

const SYM_SESS_OP_SPEC_HDR_SIZE: usize = 48;
// Splited into SymCipherCreateSessionFlf & SymAlgChainCreateSessionFlf
//
// pub struct SymCreateSessionFlf { 
//     /// Device read only portion  
 
//     /// fixed length fields, opcode specific  
// //      |cipher_session_flf
// //      |alg_chain_session_flf
//     pub op_flf: [u8; SYM_SESS_OP_SPEC_HDR_SIZE], 
 
//     pub op_type: u32, //pub enum sym_op
//     pub padding: u32, 
// }

// //
// // pub struct sym_create_session_vlf = 
// //     |cipher_session_vlf
// //     |alg_chain_session_vlf

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct AeadCreateSessionFlf { 
    /// Device read only portion  
 
    /// See AEAD_* above  
    algo: u32, 
    /// length of key  
    pub key_len: u32, 
    /// Authentication tag length  
    pub tag_len: u32, 
    /// The length of the additional authenticated data (AAD) in bytes  
    pub aad_len: u32, 
    /// encryption or decryption, See above OP_*  
    op: u32, 
    padding: u32, 
}
impl CtrlFixedLenFields for AeadCreateSessionFlf {
    fn get_algo(&self) -> u32 {
        self.algo
    }
}
impl AeadCreateSessionFlf {
    pub fn new(algo: AeadAlgo, tag_len: u32, aad_len: u32, op: CryptoOp) -> Self {
        Self {
            algo: algo as u32,
            key_len: 0, // Auto filled
            tag_len,
            aad_len,
            op: op as u32,
            padding: 0,
        }
    }
}

variable_length_fields! {
    #[derive(Default, Debug, Clone)]
    pub struct AeadCreateSessionVlf <= AeadCreateSessionFlf { 
        /// Device read only portion  
        pub key: [u8; key_len], 
    }
}

#[allow(non_camel_case_types)]
pub enum AkcipherKeyType {
    AKCIPHER_KEY_TYPE_PUBLIC = 1, 
    AKCIPHER_KEY_TYPE_PRIVATE = 2, 
}

const AKCIPHER_SESS_ALGO_SPEC_HDR_SIZE: usize = 44; 

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct AkcipherCreateSessionFlf { 
    /// Device read only portion  
 
    /// See AKCIPHER_* above  
    algo: u32, 
    key_type: u32, //pub enum AKCIPHER_KeyType
    /// length of key  
    key_len: u32, 

    //pub algo_flf: [u8; AKCIPHER_SESS_ALGO_SPEC_HDR_SIZE],
    para0: u32, //RSA: pub enum RsaPaddingAlgo *or* ECDSA: pub enum CurveType
    para1: u32, //RSA: pub enum RsaHashAlgo
    // This is because Default trait doesn't support the array with large length
    padding_bytes0: [u8; AKCIPHER_SESS_ALGO_SPEC_HDR_SIZE - 8 - 32],
    padding_bytes1: [u8; 32],
}
impl AkcipherCreateSessionFlf {
    pub fn new(key_type: AkcipherKeyType) -> Self {
        Self {
            algo: 0,
            key_type: key_type as u32,
            key_len: 0, // Auto filled
            para0: 0,
            para1: 0,
            padding_bytes0: [0; AKCIPHER_SESS_ALGO_SPEC_HDR_SIZE - 8 - 32],
            padding_bytes1: [0; 32]
        }
    }
    pub fn set_rsa(mut self, padding_algo: RsaPaddingAlgo, hash_algo: RsaHashAlgo) -> Self {
        self.algo = AkcipherAlgo::AKCIPHER_RSA as u32;
        self.para0 = padding_algo as u32;
        self.para1 = hash_algo as u32;
        self
    }
    pub fn set_ecdsa(mut self, curve_id: CurveType) -> Self {
        self.algo = AkcipherAlgo::AKCIPHER_ECDSA as u32;
        self.para0 = curve_id as u32;
        self.para1 = 0;
        self
    }
}
impl CtrlFixedLenFields for AkcipherCreateSessionFlf {
    fn get_algo(&self) -> u32 {
        self.algo
    }
}


variable_length_fields! {
    #[derive(Default, Debug, Clone)]
    pub struct AkcipherCreateSessionVlf <= AkcipherCreateSessionFlf { 
        /// Device read only portion  
        pub key: [u8; key_len], 
    }
}

//
//  Data Virtqueue
//

#[repr(u32)]
#[allow(non_camel_case_types)]
pub enum DataOpcode {
    CIPHER_ENCRYPT = 
        opcode(ServiceCode::CIPHER, 0x00),
    CIPHER_DECRYPT = 
        opcode(ServiceCode::CIPHER, 0x01),
    HASH = 
        opcode(ServiceCode::HASH, 0x00),
    MAC = 
        opcode(ServiceCode::MAC, 0x00),
    AEAD_ENCRYPT = 
        opcode(ServiceCode::AEAD, 0x00),
    AEAD_DECRYPT = 
        opcode(ServiceCode::AEAD, 0x01),
    AKCIPHER_ENCRYPT = 
        opcode(ServiceCode::AKCIPHER, 0x00),
    AKCIPHER_DECRYPT = 
        opcode(ServiceCode::AKCIPHER, 0x01),
    AKCIPHER_SIGN = 
        opcode(ServiceCode::AKCIPHER, 0x02),
    AKCIPHER_VERIFY = 
        opcode(ServiceCode::AKCIPHER, 0x03),
}

// Split DataOpcode
pub struct HashOpcode;
impl Into<u32> for HashOpcode {
    fn into(self) -> u32 {
        opcode(ServiceCode::HASH, 0x00)
    }
}

pub struct MacOpcode;
impl Into<u32> for MacOpcode {
    fn into(self) -> u32 {
        opcode(ServiceCode::MAC, 0x00)
    }
}

#[repr(u32)]
pub enum CipherOpcode {
    ENCRYPT = 
        opcode(ServiceCode::CIPHER, 0x00),
    DECRYPT = 
        opcode(ServiceCode::CIPHER, 0x01),
}
impl Into<u32> for CipherOpcode {
    fn into(self) -> u32 {
        self as u32
    }
}

#[repr(u32)]
pub enum AeadOpcode {
    ENCRYPT = 
        opcode(ServiceCode::AEAD, 0x00),
    DECRYPT = 
        opcode(ServiceCode::AEAD, 0x01),
}
impl Into<u32> for AeadOpcode {
    fn into(self) -> u32 {
        self as u32
    }
}

#[repr(u32)]
pub enum AkcipherOpcode {
    ENCRYPT = 
        opcode(ServiceCode::AKCIPHER, 0x00),
    DECRYPT = 
        opcode(ServiceCode::AKCIPHER, 0x01),
    SIGN = 
        opcode(ServiceCode::AKCIPHER, 0x02),
    VERIFY = 
        opcode(ServiceCode::AKCIPHER, 0x03),
}
impl Into<u32> for AkcipherOpcode {
    fn into(self) -> u32 {
        self as u32
    }
}

bitflags! {
    #[repr(C)]
    #[derive(Default, Pod)]
    pub struct SessionMode: u32 {
        const STATELESS = 0;
        const SESSION = 1;
    }
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct DataHeader { 
    pub opcode: u32, //pub enum DataOpcode
    /// algo should be service-specific algorithms  
    pub algo: u32, 
    pub session_id: u64, 
// FLAG_SESSION_MODE = 1, 
    /// control flag to control the request  
    pub flag: SessionMode,
    pub padding: u32, 
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct CryptoInhdr {
    pub status: u8, //pub enum status
}
impl CryptoInhdr {
    pub fn get_status(&self) -> Status {
        TryInto::<Status>::try_into(self.status).unwrap_or(Status::MAX)
    } 
}


pub trait DataFlf: Sized + Pod + Default {
    type VlfIn:  VarLenFields<Self>;
    type VlfOut: VarLenFields<Self>;
}

impl DataFlf for HashDataFlf {
    type VlfIn  = HashDataVlfIn;
    type VlfOut = HashDataVlfOut;
}
impl DataFlf for HashDataFlfStateless {
    type VlfIn  = HashDataVlfStatelessIn;
    type VlfOut = HashDataVlfStatelessOut;
}

impl DataFlf for MacDataFlf {
    type VlfIn  = MacDataVlfIn;
    type VlfOut = MacDataVlfOut;
}
impl DataFlf for MacDataFlfStateless {
    type VlfIn  = MacDataVlfStatelessIn;
    type VlfOut = MacDataVlfStatelessOut;
}

impl DataFlf for SymCipherDataFlf {
    type VlfIn  = SymCipherDataVlfIn;
    type VlfOut = SymCipherDataVlfOut;
}
impl DataFlf for SymCipherDataFlfStateless {
    type VlfIn  = SymCipherDataVlfStatelessIn;
    type VlfOut = SymCipherDataVlfStatelessOut;
}

impl DataFlf for SymAlgChainDataFlf {
    type VlfIn  = SymAlgChainDataVlfIn;
    type VlfOut = SymAlgChainDataVlfOut;
}
impl DataFlf for SymAlgChainDataFlfStateless {
    type VlfIn  = SymAlgChainDataVlfStatelessIn;
    type VlfOut = SymAlgChainDataVlfStatelessOut;
}

impl DataFlf for AeadDataFlf {
    type VlfIn  = AeadDataVlfIn;
    type VlfOut = AeadDataVlfOut;
}
impl DataFlf for AeadDataFlfStateless {
    type VlfIn  = AeadDataVlfStatelessIn;
    type VlfOut = AeadDataVlfStatelessOut;
}

impl DataFlf for AkcipherDataFlf {
    type VlfIn  = AkcipherDataVlfIn;
    type VlfOut = AkcipherDataVlfOut;
}
impl DataFlf for AkcipherDataFlfStateless {
    type VlfIn  = AkcipherDataVlfStatelessIn;
    type VlfOut = AkcipherDataVlfStatelessOut;
}


#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct HashDataFlf { 
    /// length of source data  
    src_data_len: u32, 
    /// hash result length  
    pub hash_result_len: u32, 
}
impl HashDataFlf {
    pub fn new(hash_result_len: u32) -> Self {
        Self {
            src_data_len: 0, // Auto filled
            hash_result_len,
        }
    }
}

variable_length_fields! {
    #[derive(Default, Debug, Clone)]
    pub struct HashDataVlfIn <= HashDataFlf { 
        /// Device read only portion  
        /// Source data  
        pub src_data: [u8; src_data_len],
    }
}
variable_length_fields! {
    #[derive(Default, Debug, Clone)]
    pub struct HashDataVlfOut <= HashDataFlf {
        /// Device write only portion  
        /// Hash result data  
        pub hash_result: [u8; hash_result_len],
    }
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct HashDataFlfStateless { 
    /// See HASH_* above 
    algo: u32,
    /// length of source data  
    src_data_len: u32, 
    /// hash result length  
    pub hash_result_len: u32, 
    reserved: u32, 
}
impl HashDataFlfStateless {
    pub fn new(algo: MacAlgo, hash_result_len: u32) -> Self {
        Self {
            algo: algo as u32,
            src_data_len: 0, // Auto filled
            hash_result_len,
            reserved: 0,
        }
    }
}


variable_length_fields! {
    #[derive(Default, Debug, Clone)]
    pub struct HashDataVlfStatelessIn <= HashDataFlfStateless { 
        /// Device read only portion  
        /// Source data  
        pub src_data: [u8; src_data_len],
    }
}
variable_length_fields! {
    #[derive(Default, Debug, Clone)]
    pub struct HashDataVlfStatelessOut <= HashDataFlfStateless {
        /// Device write only portion  
        /// Hash result data  
        pub hash_result: [u8; hash_result_len], 
    }
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct MacDataFlf { 
    pub hdr: HashDataFlf, 
}
 
variable_length_fields! {
    #[derive(Default, Debug, Clone)]
    pub struct MacDataVlfIn <= MacDataFlf  { 
        /// Device read only portion  
        /// Source data  
        pub src_data: [u8; hdr, src_data_len],
    }
}
variable_length_fields! {
    #[derive(Default, Debug, Clone)]
    pub struct MacDataVlfOut <= MacDataFlf  {
        /// Device write only portion  
        /// Hash result data  
        pub hash_result: [u8; hdr, hash_result_len], 
    }
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct MacDataFlfStateless { 
    // pub struct { 
        /// See MAC_* above  
        algo: u32, 
        /// length of authenticated key  
        auth_key_len: u32, 
    // }sess_para; 
 
    /// length of source data  
    src_data_len: u32, 
    /// hash result length  
    pub hash_result_len: u32, 
}
impl MacDataFlfStateless {
    pub fn new(algo: MacAlgo, hash_result_len: u32) -> Self {
        Self {
            algo: algo as u32,
            auth_key_len: 0, // Auto filled
            src_data_len: 0, // Auto filled
            hash_result_len,
        }
    }
}

variable_length_fields! {
    #[derive(Default, Debug, Clone)]
    pub struct MacDataVlfStatelessIn <= MacDataFlfStateless { 
        /// Device read only portion  
        /// The authenticated key  
        pub auth_key: [u8; auth_key_len], 
        /// Source data  
        pub src_data: [u8; src_data_len],
    }
}
variable_length_fields! {
    #[derive(Default, Debug, Clone)]
    pub struct MacDataVlfStatelessOut <= MacDataFlfStateless {
        /// Device write only portion  
        /// Hash result data  
        pub hash_result: [u8; hash_result_len], 
    }
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct CipherDataFlf { 
    /* 
     * Byte Length of valid IV/Counter data pointed to by the below iv data. 
     * 
     * For block ciphers in CBC or F8 mode, or for Kasumi in F8 mode, or for 
     *   SNOW3G in UEA2 mode, this is the length of the IV (which 
     *   must be the same as the block length of the cipher). 
     * For block ciphers in CTR mode, this is the length of the counter 
     *   (which must be the same as the block length of the cipher). 
     */ 
    iv_len: u32, 
    /// length of source data  
    src_data_len: u32, 
    /// length of destination data  
    pub dst_data_len: u32, 
    padding: u32, 
}
impl CipherDataFlf {
    pub fn new(dst_data_len: u32) -> Self {
        Self {
            iv_len: 0, // Auto filled
            src_data_len: 0, // Auto filled
            dst_data_len,
            padding: 0,
        }
    }
}
const CIPHER_DATA_FLF_PADDING_SIZE: usize = SYM_DATA_REQ_HDR_SIZE - size_of::<CipherDataFlf>();

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct SymCipherDataFlf {
    pub op_type_flf: CipherDataFlf,
    padding_bytes: [u8; CIPHER_DATA_FLF_PADDING_SIZE], 
 
    /// See above SYM_OP_*  
    op_type: u32, 
    padding: u32, 
}
impl SymCipherDataFlf {
    pub fn new(op_type_flf: CipherDataFlf) -> Self {
        Self {
            op_type_flf,
            padding_bytes: [0; CIPHER_DATA_FLF_PADDING_SIZE],
            op_type: SymOp::SYM_OP_CIPHER as u32,
            padding: 0,
        }
    }
}
 
variable_length_fields! {
    #[derive(Default, Debug, Clone)]
    pub struct SymCipherDataVlfIn <= SymCipherDataFlf { 
        /// Device read only portion  
    
        /* 
        * Initialization Vector or Counter data. 
        * 
        * For block ciphers in CBC or F8 mode, or for Kasumi in F8 mode, or for 
        *   SNOW3G in UEA2 mode, this is the Initialization Vector (IV) 
        *   value. 
        * For block ciphers in CTR mode, this is the counter. 
        * For AES-XTS, this is the 128bit tweak, i, from IEEE Std 1619-2007. 
        * 
        * The IV/Counter will be updated after every partial cryptographic 
        * operation. 
        */ 
        pub iv: [u8; op_type_flf, iv_len], 
        /// Source data  
        pub src_data: [u8; op_type_flf, src_data_len],
    }
}
variable_length_fields! {
    #[derive(Default, Debug, Clone)]
    pub struct SymCipherDataVlfOut <= SymCipherDataFlf {
        /// Device write only portion  
        /// Destination data  
        pub dst_data: [u8; op_type_flf, dst_data_len], 
    }
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct AlgChainDataFlf { 
    iv_len: u32, 
    /// Length of source data  
    src_data_len: u32, 
    /// Length of destination data  
    pub dst_data_len: u32, 
    /// Starting point for cipher processing in source data  
    pub cipher_start_src_offset: u32, 
    /// Length of the source data that the cipher will be computed on  
    pub len_to_cipher: u32, 
    /// Starting point for hash processing in source data  
    pub hash_start_src_offset: u32, 
    /// Length of the source data that the hash will be computed on  
    pub len_to_hash: u32, 
    /// Length of the additional auth data  
    aad_len: u32, 
    /// Length of the hash result  
    pub hash_result_len: u32, 
    reserved: u32, 
}
impl AlgChainDataFlf {
    pub fn new(dst_data_len: u32, cipher_start_src_offset: u32, len_to_cipher: u32, hash_start_src_offset: u32, len_to_hash: u32, hash_result_len: u32) -> Self {
        Self {
            iv_len: 0, // Auto filled
            src_data_len: 0, // Auto filled
            dst_data_len,
            cipher_start_src_offset,
            len_to_cipher,
            hash_start_src_offset,
            len_to_hash,
            aad_len: 0, // Auto filled
            hash_result_len,
            reserved: 0,
        }
    }
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct SymAlgChainDataFlf {
    pub op_type_flf: AlgChainDataFlf,
 
    /// See above SYM_OP_*  
    op_type: u32, 
    padding: u32, 
}
impl SymAlgChainDataFlf {
    pub fn new(op_type_flf: AlgChainDataFlf) -> Self {
        Self {
            op_type_flf,
            op_type: SymOp::SYM_OP_ALGORITHM_CHAINING as u32,
            padding: 0, 
        }
    }
}

variable_length_fields! {
    #[derive(Default, Debug, Clone)] 
    pub struct SymAlgChainDataVlfIn <= SymAlgChainDataFlf { 
        /// Device read only portion  
    
        /// Initialization Vector or Counter data  
        pub iv: [u8; op_type_flf, iv_len], 
        /// Source data  
        pub src_data: [u8; op_type_flf, src_data_len], 
        /// Additional authenticated data if exists  
        pub aad: [u8; op_type_flf, aad_len],
    }
}
variable_length_fields! {
    #[derive(Default, Debug, Clone)] 
    pub struct SymAlgChainDataVlfOut <= SymAlgChainDataFlf {
        /// Device write only portion  
    
        /// Destination data  
        pub dst_data: [u8; op_type_flf, dst_data_len], 
        /// Hash result data  
        pub hash_result: [u8; op_type_flf, hash_result_len], 
    }
}

const SYM_DATA_REQ_HDR_SIZE: usize = 40;
// Splited into SymCipherDataFlf & SymAlgChainDataFlf
// pub struct SymDataFlf { 
//     /// Device read only portion  
//     // virtio_crypto_cipher_data_flf | virtio_crypto_alg_chain_data_flf
//     pub op_type_flf: [u8; SYM_DATA_REQ_HDR_SIZE], 
 
//     /// See above SYM_OP_*  
//     pub op_type: u32, 
//     pub padding: u32, 
// }
 
// // virtio_crypto_cipher_data_vlf | virtio_crypto_alg_chain_data_vlf
// // pub struct sym_data_vlf { 
// //     pub op_type_vlf: [u8; sym_para_len], 
// // }

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct CipherDataFlfStateless { 
    pub para: CipherPara,
    /* 
     * Byte Length of valid IV/Counter data pointed to by the below iv data. 
     */ 
    iv_len: u32, 
    /// length of source data  
    src_data_len: u32, 
    /// length of destination data  
    pub dst_data_len: u32, 
}
impl CipherDataFlfStateless {
    pub fn new(para: CipherPara, dst_data_len: u32) -> Self {
        Self {
            para,
            iv_len: 0, // Auto filled
            src_data_len: 0, // Auto filled
            dst_data_len,
        }
    }
}
const CIPHER_DATA_FLF_STATELESS_PADDING_SIZE: usize = 
    SYM_DATE_REQ_HDR_STATELESS_SIZE - size_of::<CipherDataFlfStateless>();

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct SymCipherDataFlfStateless {
    /// Device read only portion 
    pub op_type_flf: CipherDataFlfStateless,
    // This is because Default trait doesn't support the array with large length
    padding_bytes0: [u8; CIPHER_DATA_FLF_STATELESS_PADDING_SIZE - 32],
    padding_bytes1: [u8; 32],

    /// Device write only portion  // TODO: Why the op_type is device write only?
    /// See above SYM_OP_*  
    op_type: u32,
}
impl SymCipherDataFlfStateless {
    pub fn new(op_type_flf: CipherDataFlfStateless) -> Self {
        Self {
            op_type_flf,
            padding_bytes0: [0; CIPHER_DATA_FLF_STATELESS_PADDING_SIZE - 32],
            padding_bytes1: [0; 32],
            op_type: SymOp::SYM_OP_CIPHER as u32,
        }
    }
}
 
variable_length_fields! {
    #[derive(Default, Debug, Clone)]
    pub struct SymCipherDataVlfStatelessIn <= SymCipherDataFlfStateless { 
        /// Device read only portion  
    
        /// The cipher key  
        pub cipher_key: [u8; op_type_flf, para, key_len], 
    
        /// Initialization Vector or Counter data.  
        pub iv: [u8; op_type_flf, iv_len], 
        /// Source data  
        pub src_data: [u8; op_type_flf, src_data_len],
    }
}
variable_length_fields! {
    #[derive(Default, Debug, Clone)]
    pub struct SymCipherDataVlfStatelessOut <= SymCipherDataFlfStateless { 
        /// Device write only portion  
        /// Destination data  
        pub dst_data: [u8; op_type_flf, dst_data_len], 
    }
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct AlgChainPara {
    /// See SYM_ALG_CHAIN_ORDER_* above  
    alg_chain_order: u32, 
    /// length of the additional authenticated data in bytes  
    pub aad_len: u32, //add_len

    pub cipher_para: CipherPara,

    // pub struct { 
        /// See HASH_* or MAC_* above  
        algo: u32, 
        /// length of authenticated key  
        auth_key_len: u32, 
        /// See SYM_HASH_MODE_* above  
        hash_mode: u32, 
    // }hash; 
}
impl AlgChainPara {
    pub fn new(alg_chain_order: AlgChainOrder, aad_len: u32, cipher_para: CipherPara) -> Self {
        Self {
            alg_chain_order: alg_chain_order as u32,
            aad_len,
            cipher_para,
            algo: 0,
            auth_key_len: 0,
            hash_mode: SymHashMode::SYM_HASH_MODE_PLAIN as u32,
        }
    }
    // TODO: does HASH has auth_key_len?
    pub fn set_hash(mut self, algo: HashAlgo) -> Self {
        self.hash_mode = SymHashMode::SYM_HASH_MODE_NESTED as u32;
        self.algo = algo as u32;
        self.auth_key_len = 0;
        self
    }
    pub fn set_mac(mut self, algo: MacAlgo) -> Self {
        self.hash_mode = SymHashMode::SYM_HASH_MODE_AUTH as u32;
        self.algo = algo as u32;
        self.auth_key_len = 0; // Auto filled
        self
    }
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct AlgChainDataFlfStateless { 
    pub para: AlgChainPara,
 
    iv_len: u32, 
    /// Length of source data  
    src_data_len: u32, 
    /// Length of destination data  
    pub dst_data_len: u32, 
    /// Starting point for cipher processing in source data  
    pub cipher_start_src_offset: u32, 
    /// Length of the source data that the cipher will be computed on  
    pub len_to_cipher: u32, 
    /// Starting point for hash processing in source data  
    pub hash_start_src_offset: u32, 
    /// Length of the source data that the hash will be computed on  
    pub len_to_hash: u32, 
    /// Length of the additional auth data  
    aad_len: u32, 
    /// Length of the hash result  
    pub hash_result_len: u32, 
    pub reserved: u32, 
}
impl AlgChainDataFlfStateless {
    pub fn new(para: AlgChainPara, dst_data_len: u32, cipher_start_src_offset: u32, len_to_cipher: u32, hash_start_src_offset: u32, len_to_hash: u32, hash_result_len: u32) -> Self {
        Self {
            para,
            iv_len: 0, // Auto filled
            src_data_len: 0, // Auto filled
            dst_data_len,
            cipher_start_src_offset,
            len_to_cipher,
            hash_start_src_offset,
            len_to_hash,
            aad_len: 0, // Auto filled
            hash_result_len,
            reserved: 0,
        }
    }
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct SymAlgChainDataFlfStateless {
    /// Device read only portion 
    pub op_type_flf: AlgChainDataFlfStateless,

    /// Device write only portion  // TODO: Why the op_type is device write only?
    /// See above SYM_OP_*  
    op_type: u32,
}
impl SymAlgChainDataFlfStateless {
    pub fn new(op_type_flf: AlgChainDataFlfStateless) -> Self {
        Self {
            op_type_flf,
            op_type: SymOp::SYM_OP_ALGORITHM_CHAINING as u32,
        }
    }
}

variable_length_fields! {
    #[derive(Default, Debug, Clone)]
    pub struct SymAlgChainDataVlfStatelessIn <= SymAlgChainDataFlfStateless { 
        /// Device read only portion  
    
        /// The cipher key  
        pub cipher_key: [u8; op_type_flf, para, cipher_para, key_len], 
        /// The auth key  
        pub auth_key: [u8; op_type_flf, para, auth_key_len], 
        /// Initialization Vector or Counter data  
        pub iv: [u8; op_type_flf, iv_len], 
        /// Additional authenticated data if exists  
        pub aad: [u8; op_type_flf, aad_len], 
        /// Source data  
        pub src_data: [u8; op_type_flf, src_data_len],
    }
}
variable_length_fields! {
    #[derive(Default, Debug, Clone)]
    pub struct SymAlgChainDataVlfStatelessOut <= SymAlgChainDataFlfStateless {
        /// Device write only portion  
    
        /// Destination data  
        pub dst_data: [u8; op_type_flf, dst_data_len], 
        /// Hash result data  
        pub hash_result: [u8; op_type_flf, hash_result_len], 
    }
}

const SYM_DATE_REQ_HDR_STATELESS_SIZE: usize = 72; 
// Splited into SymCipherDataFlfStateless & SymAlgChainDataFlfStateless
//
// pub struct SymDataFlfStateless { 
//     /// Device read only portion 

//     //cipher_data_flf_stateless | alg_chain_data_flf_stateless
//     pub op_type_flf: [u8; SYM_DATE_REQ_HDR_STATELESS_SIZE], 
 
//     /// Device write only portion  
//     /// See above SYM_OP_*  
//     pub op_type: u32, 
// }
 
// //cipher_data_vlf_stateless | alg_chain_data_vlf_stateless
// // pub struct sym_data_vlf_stateless { 
// //     pub op_type_vlf: [u8; sym_para_len], 
// // }

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct AeadDataFlf { 
    /* 
     * Byte Length of valid IV data. 
     * 
     * For GCM mode, this is either 12 (for 96-bit IVs) or 16, in which 
     *   case iv points to J0. 
     * For CCM mode, this is the length of the nonce, which can be in the 
     *   range 7 to 13 inclusive. 
     */ 
    iv_len: u32, 
    /// length of additional auth data  
    aad_len: u32, 
    /// length of source data  
    src_data_len: u32, 
    /// length of dst data, this should be at least src_data_len + tag_len  
    pub dst_data_len: u32, 
    /// Authentication tag length  
    pub tag_len: u32, 
    reserved: u32, 
}
impl AeadDataFlf {
    pub fn new(dst_data_len: u32, tag_len: u32) -> Self {
        Self {
            iv_len: 0, // Auto filled
            aad_len: 0, // Auto filled
            src_data_len: 0, // Auto filled
            dst_data_len,
            tag_len,
            reserved: 0,
        }
    }
}
 
variable_length_fields! {
    #[derive(Default, Debug, Clone)]
    pub struct AeadDataVlfIn <= AeadDataFlf { 
        /// Device read only portion  
    
        /* 
        * Initialization Vector data. 
        * 
        * For GCM mode, this is either the IV (if the length is 96 bits) or J0 
        *   (for other sizes), where J0 is as defined by NIST SP800-38D. 
        *   Regardless of the IV length, a full 16 bytes needs to be allocated. 
        * For CCM mode, the first byte is reserved, and the nonce should be 
        *   written starting at &iv[1] (to allow space for the implementation 
        *   to write in the flags in the first byte).  Note that a full 16 bytes 
        *   should be allocated, even though the iv_len field will have 
        *   a value less than this. 
        * 
        * The IV will be updated after every partial cryptographic operation. 
        */ 
        pub iv: [u8; iv_len], 
        /// Source data  
        pub src_data: [u8; src_data_len], 
        /// Additional authenticated data if exists  
        pub aad: [u8; aad_len],
    }
}
variable_length_fields! {
    #[derive(Default, Debug, Clone)]
    pub struct AeadDataVlfOut <= AeadDataFlf { 
        /// Device write only portion  
        /// Pointer to output data  
        pub dst_data: [u8; dst_data_len], 
    }
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct AeadPara {
    /// See AEAD_* above  
    algo: u32, 
    /// length of key  
    key_len: u32, 
    /// encrypt or decrypt, See above OP_*  
    op: u32, 
}
impl AeadPara {
    pub fn new(algo: AeadAlgo, op: CryptoOp) -> Self {
        Self {
            algo: algo as u32,
            key_len: 0, // Auto filled
            op: op as u32,
        }
    }
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct AeadDataFlfStateless { 
    pub para: AeadPara,
    /// Byte Length of valid IV data.  
    iv_len: u32, 
    /// Authentication tag length  
    pub tag_len: u32, 
    /// length of additional auth data  
    aad_len: u32, 
    /// length of source data  
    src_data_len: u32, 
    /// length of dst data, this should be at least src_data_len + tag_len  
    pub dst_data_len: u32, 
}
impl AeadDataFlfStateless {
    pub fn new(para: AeadPara, tag_len: u32, dst_data_len: u32) -> Self {
        Self {
            para,
            iv_len: 0, // Auto filled
            tag_len,
            aad_len: 0, // Auto filled
            src_data_len: 0, // Auto filled
            dst_data_len,
        }
    }
}
 
variable_length_fields! {
    #[derive(Default, Debug, Clone)]
    pub struct AeadDataVlfStatelessIn <= AeadDataFlfStateless { 
        /// Device read only portion  
    
        /// The cipher key  
        pub key: [u8; para, key_len], 
        /// Initialization Vector data.  
        pub iv: [u8; iv_len], 
        /// Source data  
        pub src_data: [u8; src_data_len], 
        /// Additional authenticated data if exists  
        pub aad: [u8; aad_len],
    }
}
variable_length_fields! {
    #[derive(Default, Debug, Clone)]
    pub struct AeadDataVlfStatelessOut <= AeadDataFlfStateless {
        /// Device write only portion  
        /// Pointer to output data  
        pub dst_data: [u8; dst_data_len], 
    }
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct AkcipherDataFlf { 
    /// length of source data  
    src_data_len: u32, 
    /// length of dst data  
    pub dst_data_len: u32, 
}
impl AkcipherDataFlf {
    pub fn new(dst_data_len: u32) -> Self {
        Self {
            src_data_len: 0, // Auto filled
            dst_data_len,
        }
    }
}
 
variable_length_fields! {
    #[derive(Default, Debug, Clone)]
    pub struct AkcipherDataVlfIn <= AkcipherDataFlf { 
        /// Device read only portion  
        /// Source data  
        pub src_data: [u8; src_data_len],
    }
}
variable_length_fields! {
    #[derive(Default, Debug, Clone)]
    pub struct AkcipherDataVlfOut <= AkcipherDataFlf {
        /// Device write only portion  
        /// Pointer to output data  
        pub dst_data: [u8; dst_data_len], 
    }
}

#[allow(non_camel_case_types)]
pub enum RsaPaddingAlgo {
    RSA_RAW_PADDING = 0, 
    RSA_PKCS1_PADDING = 1, 
}

#[allow(non_camel_case_types)]
pub enum RsaHashAlgo {
    RSA_NO_HASH = 0, 
    RSA_MD2 = 1, 
    RSA_MD3 = 2, 
    RSA_MD4 = 3, 
    RSA_MD5 = 4, 
    RSA_SHA1 = 5, 
    RSA_SHA256 = 6, 
    RSA_SHA384 = 7, 
    RSA_SHA512 = 8, 
    RSA_SHA224 = 9, 
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct RsaSessionPara { 
    padding_algo: u32, //pub enum RsaPaddingAlgo
    hash_algo: u32, //pub enum RsaHashAlgo
}

#[allow(non_camel_case_types)]
pub enum CurveType {
    CURVE_UNKNOWN = 0, 
    CURVE_NIST_P192 = 1, 
    CURVE_NIST_P224 = 2, 
    CURVE_NIST_P256 = 3, 
    CURVE_NIST_P384 = 4, 
    CURVE_NIST_P521 = 5,
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct EcdsaSessionPara { 
    /// See CURVE_* above  
    curve_id: u32, //pub enum CurveType
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct AkcipherDataPara {
    /// See VIRTIO_CYRPTO_AKCIPHER* above  
    algo: u32, 
    /// See AKCIPHER_KEY_TYPE_* above  
    key_type: u32, 
    /// length of key  
    key_len: u32, 

    /// algothrim specific parameters described above 
    para0: u32, //RSA: pub enum RsaPaddingAlgo *or* ECDSA: pub enum CurveType
    para1: u32, //RSA: pub enum RsaHashAlgo
}
impl AkcipherDataPara {
    pub fn new(key_type: AkcipherKeyType) -> Self {
        Self {
            algo: 0,
            key_type: key_type as u32,
            key_len: 0, // Auto filled
            para0: 0,
            para1: 0,
        }
    }
    pub fn set_rsa(mut self, padding_algo: RsaPaddingAlgo, hash_algo: RsaHashAlgo) -> Self {
        self.algo = AkcipherAlgo::AKCIPHER_RSA as u32;
        self.para0 = padding_algo as u32;
        self.para1 = hash_algo as u32;
        self
    }
    pub fn set_ecdsa(mut self, curve_id: CurveType) -> Self {
        self.algo = AkcipherAlgo::AKCIPHER_ECDSA as u32;
        self.para0 = curve_id as u32;
        self.para1 = 0;
        self
    }
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct AkcipherDataFlfStateless { 
    pub para: AkcipherDataPara,

    /// length of source data  
    src_data_len: u32, 
    /// length of destination data  
    pub dst_data_len: u32, 
}
impl AkcipherDataFlfStateless {
    pub fn new(para: AkcipherDataPara, dst_data_len: u32) -> Self {
        Self {
            para,
            src_data_len: 0, // Auto filled
            dst_data_len,
        }
    }
}

variable_length_fields! {
    #[derive(Default, Debug, Clone)]
    pub struct AkcipherDataVlfStatelessIn <= AkcipherDataFlfStateless { 
        /// Device read only portion  
        pub akcipher_key: [u8; para, key_len], 
    
        /// Source data  
        pub src_data: [u8; src_data_len],
    }
}
variable_length_fields! {
    #[derive(Default, Debug, Clone)]
    pub struct AkcipherDataVlfStatelessOut <= AkcipherDataFlfStateless { 
        /// Device write only portion  
        pub dst_data: [u8; dst_data_len], 
    }
}