use alloc::vec::Vec;

#[allow(non_camel_case_types)]
enum ServiceCode {
    /*CIPHER (Symmetric Key Cipher) service*/
    CIPHER = 0,
    /*HASH service*/
    HASH = 1,
    /*MAC (Message Authentication Codes) service*/
    MAC = 2,
    /*AEAD (Authenticated Encryption with Associated Data) service*/
    AEAD = 3,
    /*AKCIPHER (Asymmetric Key Cipher) service*/
    AKCIPHER = 4,
}

#[allow(non_camel_case_types)]
enum CipherAlgo {
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

#[allow(non_camel_case_types)]
enum HashAlgo {
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

#[allow(non_camel_case_types)]
enum MacAlgo {
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

#[allow(non_camel_case_types)]
enum AeadAlgo {
    NO_AEAD = 0,
    AEAD_GCM = 1,
    AEAD_CCM = 2,
    AEAD_CHACHA20_POLY1305 = 3,
}

#[allow(non_camel_case_types)]
enum AkcipherAlgo {
    NO_AKCIPHER = 0,
    AKCIPHER_RSA = 1,
    AKCIPHER_ECDSA = 2,
}

#[allow(non_camel_case_types)]
enum Status {
    OK = 0,
    ERR = 1,
    BADMSG = 2,
    NOTSUPP = 3,
    INVSESS = 4,
    NOSPC = 5,
    KEY_REJECTED = 6,
    MAX
}

const fn opcode(service: ServiceCode, op: isize) -> isize {
    ((service as isize) << 8) | op
}
#[allow(non_camel_case_types)]
enum ControlOpcode {
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

macro_rules! variable_length_fields {
    (
        $(#[$outer:meta])*
        $vis:vis struct $StructName:ident <= $T:ty {
            $(
                $(#[$inner:ident $($args:tt)*])*
                $fvis:vis $field:ident: [u8; $($len:ident),+],
            )*
        }
    ) => {
        $(#[$outer])*
        $vis struct $StructName {
            $(
                $fvis $field: Vec<u8>,
            )*
        }

        impl $StructName {
            #[allow(unused_assignments)]
            fn from_bytes(bytes: &[u8], packet: $T) -> Self {
                let mut begin: usize = 0;
                $(
                    let len = packet$(.$len)+ as usize;
                    let $field = bytes[begin..begin+len].to_vec();
                    begin += len;
                )*
                $StructName {
                    $($field,)*
                }
            }
        }

    }
}

//
//  Control Virtqueue
//

struct ControlHeader {
    pub opcode: u32, //enum ControlOpcode
    /* algo should be service-specific algorithms */ 
    pub algo: u32,
    pub flag: u32,
    pub reserved: u32,
}

struct CreateSessionInput { 
    pub session_id: u64, 
    pub status: u32, 
    pub padding: u32, 
}

struct DestroySessionFlf { 
    /* Device read only portion */ 
    pub session_id: u64, 
}
 
struct DestroySessionInput { 
    /* Device write only portion */ 
    pub status: u8, 
}

struct HashCreateSessionFlf { 
    /* Device read only portion */ 
 
    pub para: HashPara, 
    /* hash result length */ 
    pub hash_result_len: u32, 
}

struct MacCreateSessionFlf { 
    /* Device read only portion */ 
 
    /* See MAC_* above */ 
    pub algo: u32, 
    /* hash result length */ 
    pub hash_result_len: u32, 
    /* length of authenticated key */ 
    pub auth_key_len: u32, 
    pub padding: u32, 
}

variable_length_fields! {
    struct MacCreateSessionVlf <= MacCreateSessionFlf { 
        /* Device read only portion */ 
     
        /* The authenticated key */ 
        pub auth_key: [u8; auth_key_len], 
    }
}

#[allow(non_camel_case_types)]
enum CryptoOp {
    OP_ENCRYPT = 1, 
    OP_DECRYPT = 2, 
}

struct CipherPara {
    /* See CIPHER* above */ 
    pub algo: u32, 
    /* length of key */ 
    pub key_len: u32, 

    /* encryption or decryption */ 
    pub op: u32, //enum CRYPTO_OP
}

struct CipherSessionFlf { 
    /* Device read only portion */ 
    pub para: CipherPara,
    pub padding: u32, 
}
 
variable_length_fields! {
    struct CipherSessionVlf <= CipherSessionFlf { 
        /* Device read only portion */ 
    
        /* The cipher key */ 
        pub cipher_key: [u8; para, key_len], 
    }
}

#[allow(non_camel_case_types)]
enum AlgChainOrder {
    SYM_ALG_CHAIN_ORDER_HASH_THEN_CIPHER = 1, 
    SYM_ALG_CHAIN_ORDER_CIPHER_THEN_HASH = 2, 
}

#[allow(non_camel_case_types)]
enum SymHashMode {
    /* Plain hash */ 
    SYM_HASH_MODE_PLAIN = 1, 
    /* Authenticated hash (mac) */ 
    SYM_HASH_MODE_AUTH = 2, 
    /* Nested hash */ 
    SYM_HASH_MODE_NESTED = 3, 
}

const ALG_CHAIN_SESS_OP_SPEC_HDR_SIZE: usize = 16; 

struct AlgChainSessionFlf { 
    /* Device read only portion */ 

    pub alg_chain_order: u32, //enum alg_chain_order

    pub hash_mode: u32, //enum sym_hash_mode
    pub cipher_hdr: CipherSessionFlf,
 
    /* fixed length fields, algo specific */ 
    // TODO: Mac or Hash
    pub algo_flf: MacCreateSessionFlf, 
 
    /* length of the additional authenticated data (AAD) in bytes */ 
    pub aad_len: u32, 
    pub padding: u32, 
}

variable_length_fields!{
    struct AlgChainSessionVlf <= AlgChainSessionFlf { 
        /* Device read only portion */ 
    
        /* The cipher key */ 
        pub cipher_key: [u8; cipher_hdr, para, key_len], 
        /* The authenticated key */ 
        pub auth_key: [u8; algo_flf, auth_key_len], 
    }
}

const SYM_SESS_OP_SPEC_HDR_SIZE: usize = 48; 

#[allow(non_camel_case_types)]
enum SymOp {
    /* No operation */ 
    SYM_OP_NONE = 0, 
    /* Cipher only operation on the data */ 
    SYM_OP_CIPHER = 1, 
    /* Chain any cipher with any hash or mac operation. The order 
    depends on the value of alg_chain_order param */ 
    SYM_OP_ALGORITHM_CHAINING = 2, 
}

struct SymCreateSessionFlf { 
    /* Device read only portion */ 
 
    /* fixed length fields, opcode specific */ 
//      |cipher_session_flf
//      |alg_chain_session_flf
    pub op_flf: [u8; SYM_SESS_OP_SPEC_HDR_SIZE], 
 
    pub op_type: u32, //snum sym_op
    pub padding: u32, 
}

// TODO:
// struct sym_create_session_vlf = 
//     |cipher_session_vlf
//     |alg_chain_session_vlf

struct AeadCreateSessionFlf { 
    /* Device read only portion */ 
 
    /* See AEAD_* above */ 
    pub algo: u32, 
    /* length of key */ 
    pub key_len: u32, 
    /* Authentication tag length */ 
    pub tag_len: u32, 
    /* The length of the additional authenticated data (AAD) in bytes */ 
    pub aad_len: u32, 
    /* encryption or decryption, See above OP_* */ 
    pub op: u32, 
    pub padding: u32, 
}

variable_length_fields! {
    struct AeadCreateSessionVlf <= AeadCreateSessionFlf { 
    /* Device read only portion */ 
    pub key: [u8; key_len], 
    }
}

#[allow(non_camel_case_types)]
enum AkcipherKeyType {
    AKCIPHER_KEY_TYPE_PUBLIC = 1, 
    AKCIPHER_KEY_TYPE_PRIVATE = 2, 
}

const AKCIPHER_SESS_ALGO_SPEC_HDR_SIZE: usize = 44; 

struct AkcipherCreateSessionFlf { 
    /* Device read only portion */ 
 
    /* See AKCIPHER_* above */ 
    pub algo: u32, //enum AKCIPHER_KeyType
    pub key_type: u32, 
    /* length of key */ 
    pub key_len: u32, 
 
    pub algo_flf: [u8; AKCIPHER_SESS_ALGO_SPEC_HDR_SIZE], 
}

variable_length_fields! {
    struct AkcipherCreateSessionVlf <=  AkcipherCreateSessionFlf { 
        /* Device read only portion */ 
        pub key: [u8; key_len], 
    }
}

//
//  Data Virtqueue
//

#[allow(non_camel_case_types)]
enum DataOpcode {
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

struct OpHeader { 
    pub opcode: u32, //enum DataOpcode
    /* algo should be service-specific algorithms */ 
    pub algo: u32, 
    pub session_id: u64, 
// FLAG_SESSION_MODE = 1, 
    /* control flag to control the request */ 
    pub flag: u32, 
    pub padding: u32, 
}

struct HashDataFlf { 
    /* length of source data */ 
    pub src_data_len: u32, 
    /* hash result length */ 
    pub hash_result_len: u32, 
}

variable_length_fields! {
    struct HashDataVlf <= HashDataFlf { 
        /* Device read only portion */ 
        /* Source data */ 
        pub src_data: [u8; src_data_len], 
    
        /* Device write only portion */ 
        /* Hash result data */ 
        pub hash_result: [u8; hash_result_len],
    }
}

struct HashPara {
    /* See HASH_* above */
    pub algo: u32,
}

struct HashDataFlfStateless { 
    pub para: HashPara,
    /* length of source data */ 
    pub src_data_len: u32, 
    /* hash result length */ 
    pub hash_result_len: u32, 
    pub reserved: u32, 
}

variable_length_fields! {
    struct HashDataVlfStateless <= HashDataFlfStateless { 
        /* Device read only portion */ 
        /* Source data */ 
        pub src_data: [u8; src_data_len], 
    
        /* Device write only portion */ 
        /* Hash result data */ 
        pub hash_result: [u8; hash_result_len], 
    }
}

struct MacDataFlf { 
    pub hdr: HashDataFlf, 
}
 
variable_length_fields! {
    struct MacDataVlf <= MacDataFlf  { 
        /* Device read only portion */ 
        /* Source data */ 
        pub src_data: [u8; hdr, src_data_len], 
    
        /* Device write only portion */ 
        /* Hash result data */ 
        pub hash_result: [u8; hdr, hash_result_len], 
    }
}

struct MacDataFlfStateless { 
    // struct { 
        /* See MAC_* above */ 
        pub algo: u32, 
        /* length of authenticated key */ 
        pub auth_key_len: u32, 
    // }sess_para; 
 
    /* length of source data */ 
    pub src_data_len: u32, 
    /* hash result length */ 
    pub hash_result_len: u32, 
}

variable_length_fields! {
    struct MacDataVlfStateless <= MacDataFlfStateless { 
        /* Device read only portion */ 
        /* The authenticated key */ 
        pub auth_key: [u8; auth_key_len], 
        /* Source data */ 
        pub src_data: [u8; src_data_len], 
    
        /* Device write only portion */ 
        /* Hash result data */ 
        pub hash_result: [u8; hash_result_len], 
    }
}

struct CipherDataFlf { 
    /* 
     * Byte Length of valid IV/Counter data pointed to by the below iv data. 
     * 
     * For block ciphers in CBC or F8 mode, or for Kasumi in F8 mode, or for 
     *   SNOW3G in UEA2 mode, this is the length of the IV (which 
     *   must be the same as the block length of the cipher). 
     * For block ciphers in CTR mode, this is the length of the counter 
     *   (which must be the same as the block length of the cipher). 
     */ 
    pub iv_len: u32, 
    /* length of source data */ 
    pub src_data_len: u32, 
    /* length of destination data */ 
    pub dst_data_len: u32, 
    pub padding: u32, 
}
 
variable_length_fields! {
    struct CipherDataVlf <= CipherDataFlf { 
        /* Device read only portion */ 
    
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
        pub iv: [u8; iv_len], 
        /* Source data */ 
        pub src_data: [u8; src_data_len], 
    
        /* Device write only portion */ 
        /* Destination data */ 
        pub dst_data: [u8; dst_data_len], 
    }
}

struct AlgChainDataFlf { 
    pub iv_len: u32, 
    /* Length of source data */ 
    pub src_data_len: u32, 
    /* Length of destination data */ 
    pub dst_data_len: u32, 
    /* Starting point for cipher processing in source data */ 
    pub cipher_start_src_offset: u32, 
    /* Length of the source data that the cipher will be computed on */ 
    pub len_to_cipher: u32, 
    /* Starting point for hash processing in source data */ 
    pub hash_start_src_offset: u32, 
    /* Length of the source data that the hash will be computed on */ 
    pub len_to_hash: u32, 
    /* Length of the additional auth data */ 
    pub aad_len: u32, 
    /* Length of the hash result */ 
    pub hash_result_len: u32, 
    pub reserved: u32, 
}


variable_length_fields! { 
    struct AlgChainDataVlf <= AlgChainDataFlf { 
        /* Device read only portion */ 
    
        /* Initialization Vector or Counter data */ 
        pub iv: [u8; iv_len], 
        /* Source data */ 
        pub src_data: [u8; src_data_len], 
        /* Additional authenticated data if exists */ 
        pub aad: [u8; aad_len], 
    
        /* Device write only portion */ 
    
        /* Destination data */ 
        pub dst_data: [u8; dst_data_len], 
        /* Hash result data */ 
        pub hash_result: [u8; hash_result_len], 
    }
}

const SYM_DATA_REQ_HDR_SIZE: usize = 40;

struct SymDataFlf { 
    /* Device read only portion */ 
 
    pub op_type_flf: [u8; SYM_DATA_REQ_HDR_SIZE], 
 
    /* See above SYM_OP_* */ 
    pub op_type: u32, 
    pub padding: u32, 
}
 
// TODO: similar to sym_create_session_vlf
// struct sym_data_vlf { 
//     pub op_type_vlf: [u8; sym_para_len], 
// }

struct CipherDataFlfStateless { 
    pub para: CipherPara,
    /* 
     * Byte Length of valid IV/Counter data pointed to by the below iv data. 
     */ 
    pub iv_len: u32, 
    /* length of source data */ 
    pub src_data_len: u32, 
    /* length of destination data */ 
    pub dst_data_len: u32, 
}
 
variable_length_fields! {
    struct CipherDataVlfStateless <= CipherDataFlfStateless { 
        /* Device read only portion */ 
    
        /* The cipher key */ 
        pub cipher_key: [u8; para, key_len], 
    
        /* Initialization Vector or Counter data. */ 
        pub iv: [u8; iv_len], 
        /* Source data */ 
        pub src_data: [u8; src_data_len], 
    
        /* Device write only portion */ 
        /* Destination data */ 
        pub dst_data: [u8; dst_data_len], 
    }
}

struct AlgChainPara {
    /* See SYM_ALG_CHAIN_ORDER_* above */ 
    pub alg_chain_order: u32, 
    /* length of the additional authenticated data in bytes */ 
    pub para_aad_len: u32, //add_len

    pub cipher_para: CipherPara,

    // struct { 
        /* See HASH_* or MAC_* above */ 
        pub algo: u32, 
        /* length of authenticated key */ 
        pub auth_key_len: u32, 
        /* See SYM_HASH_MODE_* above */ 
        pub hash_mode: u32, 
    // }hash; 
}

struct AlgChainDataFlfStateless { 
    pub para: AlgChainPara,
 
    pub iv_len: u32, 
    /* Length of source data */ 
    pub src_data_len: u32, 
    /* Length of destination data */ 
    pub dst_data_len: u32, 
    /* Starting point for cipher processing in source data */ 
    pub cipher_start_src_offset: u32, 
    /* Length of the source data that the cipher will be computed on */ 
    pub len_to_cipher: u32, 
    /* Starting point for hash processing in source data */ 
    pub hash_start_src_offset: u32, 
    /* Length of the source data that the hash will be computed on */ 
    pub len_to_hash: u32, 
    /* Length of the additional auth data */ 
    pub aad_len: u32, 
    /* Length of the hash result */ 
    pub hash_result_len: u32, 
    pub reserved: u32, 
}

variable_length_fields! {
    struct AlgChainDataVlfStateless <= AlgChainDataFlfStateless { 
        /* Device read only portion */ 
    
        /* The cipher key */ 
        pub cipher_key: [u8; para, cipher_para, key_len], 
        /* The auth key */ 
        pub auth_key: [u8; para, auth_key_len], 
        /* Initialization Vector or Counter data */ 
        pub iv: [u8; iv_len], 
        /* Additional authenticated data if exists */ 
        pub aad: [u8; aad_len], 
        /* Source data */ 
        pub src_data: [u8; src_data_len], 
    
        /* Device write only portion */ 
    
        /* Destination data */ 
        pub dst_data: [u8; dst_data_len], 
        /* Hash result data */ 
        pub hash_result: [u8; hash_result_len], 
    }
}

const SYM_DATE_REQ_HDR_STATELESS_SIZE: usize = 72; 

struct SymDataFlfStateless { 
    /* Device read only portion */

    //TODO: cipher_data_flf_stateless | alg_chain_data_flf_stateless
    pub op_type_flf: [u8; SYM_DATE_REQ_HDR_STATELESS_SIZE], 
 
    /* Device write only portion */ 
    /* See above SYM_OP_* */ 
    pub op_type: u32, 
}
 
//TODO: cipher_data_vlf_stateless | alg_chain_data_vlf_stateless
// struct sym_data_vlf_stateless { 
//     pub op_type_vlf: [u8; sym_para_len], 
// }

struct AeadDataFlf { 
    /* 
     * Byte Length of valid IV data. 
     * 
     * For GCM mode, this is either 12 (for 96-bit IVs) or 16, in which 
     *   case iv points to J0. 
     * For CCM mode, this is the length of the nonce, which can be in the 
     *   range 7 to 13 inclusive. 
     */ 
    pub iv_len: u32, 
    /* length of additional auth data */ 
    pub aad_len: u32, 
    /* length of source data */ 
    pub src_data_len: u32, 
    /* length of dst data, this should be at least src_data_len + tag_len */ 
    pub dst_data_len: u32, 
    /* Authentication tag length */ 
    pub tag_len: u32, 
    pub reserved: u32, 
}
 
variable_length_fields! {
    struct AeadDataVlf <= AeadDataFlf { 
        /* Device read only portion */ 
    
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
        /* Source data */ 
        pub src_data: [u8; src_data_len], 
        /* Additional authenticated data if exists */ 
        pub aad: [u8; aad_len], 
    
        /* Device write only portion */ 
        /* Pointer to output data */ 
        pub dst_data: [u8; dst_data_len], 
    }
}

struct AeadPara {
    /* See AEAD_* above */ 
    pub algo: u32, 
    /* length of key */ 
    pub key_len: u32, 
    /* encrypt or decrypt, See above OP_* */ 
    pub op: u32, 
}

struct AeadDataFlfStateless { 
    pub para: AeadPara,
    /* Byte Length of valid IV data. */ 
    pub iv_len: u32, 
    /* Authentication tag length */ 
    pub tag_len: u32, 
    /* length of additional auth data */ 
    pub aad_len: u32, 
    /* length of source data */ 
    pub src_data_len: u32, 
    /* length of dst data, this should be at least src_data_len + tag_len */ 
    pub dst_data_len: u32, 
}
 
variable_length_fields! {
    struct AeadDataVlfStateless <= AeadDataFlfStateless { 
        /* Device read only portion */ 
    
        /* The cipher key */ 
        pub key: [u8; para, key_len], 
        /* Initialization Vector data. */ 
        pub iv: [u8; iv_len], 
        /* Source data */ 
        pub src_data: [u8; src_data_len], 
        /* Additional authenticated data if exists */ 
        pub aad: [u8; aad_len], 
    
        /* Device write only portion */ 
        /* Pointer to output data */ 
        pub dst_data: [u8; dst_data_len], 
    }
}

struct AkcipherDataFlf { 
    /* length of source data */ 
    pub src_data_len: u32, 
    /* length of dst data */ 
    pub dst_data_len: u32, 
}
 
variable_length_fields! {
    struct AkcipherDataVlf <= AkcipherDataFlf { 
        /* Device read only portion */ 
        /* Source data */ 
        pub src_data: [u8; src_data_len], 
    
        /* Device write only portion */ 
        /* Pointer to output data */ 
        pub dst_data: [u8; dst_data_len], 
    }
}

#[allow(non_camel_case_types)]
enum RsaPaddingAlgo {
    RSA_RAW_PADDING = 0, 
    RSA_PKCS1_PADDING = 1, 
}

#[allow(non_camel_case_types)]
enum RsaHashAlgo {
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

struct RsaSessionPara { 
    pub padding_algo: u32, //enum RsaPaddingAlgo
    pub hash_algo: u32, //enum RsaHashAlgo
}

#[allow(non_camel_case_types)]
enum CurveType {
    CURVE_UNKNOWN = 0, 
    CURVE_NIST_P192 = 1, 
    CURVE_NIST_P224 = 2, 
    CURVE_NIST_P256 = 3, 
    CURVE_NIST_P384 = 4, 
    CURVE_NIST_P521 = 5,
}

struct EcdsaSessionPara { 
    /* See CURVE_* above */ 
    pub curve_id: u32, //enum CurveType
}

struct AkcipherDataPara {
    /* See VIRTIO_CYRPTO_AKCIPHER* above */ 
    pub algo: u32, 
    /* See AKCIPHER_KEY_TYPE_* above */ 
    pub key_type: u32, 
    /* length of key */ 
    pub key_len: u32, 

    /* algothrim specific parameters described above */
    // TODO
    pub para0: u32, //enum RsaPaddingAlgo *or* enum CurveType
    pub para1: u32, //enum RsaHashAlgo
}

struct AkcipherDataFlfStateless { 
    pub para: AkcipherDataPara,

    /* length of source data */ 
    pub src_data_len: u32, 
    /* length of destination data */ 
    pub dst_data_len: u32, 
}

variable_length_fields! {
    struct AkcipherDataVlfStateless <= AkcipherDataFlfStateless { 
        /* Device read only portion */ 
        pub akcipher_key: [u8; para, key_len], 
    
        /* Source data */ 
        pub src_data: [u8; src_data_len], 
    
        /* Device write only portion */ 
        pub dst_data: [u8; dst_data_len], 
    }
}