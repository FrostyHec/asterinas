use core::{hint::spin_loop, marker::PhantomData};

use alloc::vec;
use log::debug;
use ostd::{mm::{DmaDirection, DmaStream, DmaStreamSlice, FrameAllocOptions, Infallible, VmReader, VmWriter, PAGE_SIZE}, sync::SpinLock, Pod};

use crate::queue::VirtQueue;

use super::{device::CryptoDevice, header::{*}};

pub trait CryptoSessionTrait: Sized {
    type CtrlFlf: Sized + Pod + Default + CtrlFixedLenFields;
    type CtrlVlf: VarLenFields<Self::CtrlFlf>;
    const CREATE_SESSION:  ControlOpcode;
    const DESTROY_SESSION: ControlOpcode;

    type DataFlf: Sized + Pod + Default;
    type DataVlfIn:  VarLenFields<Self::DataFlf>;
    type DataVlfOut: VarLenFields<Self::DataFlf>;

    type DataFlfStateless: Sized + Pod + Default;
    type DataVlfStatelessIn:  VarLenFields<Self::DataFlfStateless>;
    type DataVlfStatelessOut: VarLenFields<Self::DataFlfStateless>;
}

#[derive(Debug)]
pub struct HashSession;
impl CryptoSessionTrait for HashSession {
    type CtrlFlf = HashCreateSessionFlf;
    type CtrlVlf = HashNoVlf;
    const CREATE_SESSION:  ControlOpcode = ControlOpcode::HASH_CREATE_SESSION;
    const DESTROY_SESSION: ControlOpcode = ControlOpcode::HASH_DESTROY_SESSION;

    type DataFlf = HashDataFlf;
    type DataVlfIn  = HashDataVlfIn;
    type DataVlfOut = HashDataVlfOut;

    type DataFlfStateless = HashDataFlfStateless;
    type DataVlfStatelessIn  = HashDataVlfStatelessIn;
    type DataVlfStatelessOut = HashDataVlfStatelessOut;
}

#[derive(Debug)]
pub struct MacSession;
impl CryptoSessionTrait for MacSession {
    type CtrlFlf = MacCreateSessionFlf;
    type CtrlVlf = MacCreateSessionVlf;
    const CREATE_SESSION:  ControlOpcode = ControlOpcode::MAC_CREATE_SESSION;
    const DESTROY_SESSION: ControlOpcode = ControlOpcode::MAC_DESTROY_SESSION;

    type DataFlf = MacDataFlf;
    type DataVlfIn  = MacDataVlfIn;
    type DataVlfOut = MacDataVlfOut;

    type DataFlfStateless = MacDataFlfStateless;
    type DataVlfStatelessIn  = MacDataVlfStatelessIn;
    type DataVlfStatelessOut = MacDataVlfStatelessOut;
}

#[derive(Debug)]
pub struct SymCipherSession;
impl CryptoSessionTrait for SymCipherSession {
    type CtrlFlf = SymCipherCreateSessionFlf;
    type CtrlVlf = SymCipherCreateSessionVlf;
    const CREATE_SESSION:  ControlOpcode = ControlOpcode::CIPHER_CREATE_SESSION;
    const DESTROY_SESSION: ControlOpcode = ControlOpcode::CIPHER_DESTROY_SESSION;

    type DataFlf = SymCipherDataFlf;
    type DataVlfIn  = SymCipherDataVlfIn;
    type DataVlfOut = SymCipherDataVlfOut;

    type DataFlfStateless = SymCipherDataFlfStateless;
    type DataVlfStatelessIn  = SymCipherDataVlfStatelessIn;
    type DataVlfStatelessOut = SymCipherDataVlfStatelessOut;
}

#[derive(Debug)]
pub struct SymAlgChainSession;
impl CryptoSessionTrait for SymAlgChainSession {
    type CtrlFlf = SymAlgChainCreateSessionFlf;
    type CtrlVlf = SymAlgChainCreateSessionVlf;
    const CREATE_SESSION:  ControlOpcode = ControlOpcode::CIPHER_CREATE_SESSION;
    const DESTROY_SESSION: ControlOpcode = ControlOpcode::CIPHER_DESTROY_SESSION;

    type DataFlf = SymAlgChainDataFlf;
    type DataVlfIn  = SymAlgChainDataVlfIn;
    type DataVlfOut = SymAlgChainDataVlfOut;

    type DataFlfStateless = SymAlgChainDataFlfStateless;
    type DataVlfStatelessIn  = SymAlgChainDataVlfStatelessIn;
    type DataVlfStatelessOut = SymAlgChainDataVlfStatelessOut;
}

pub struct AeadSession;
impl CryptoSessionTrait for AeadSession {
    type CtrlFlf = AeadCreateSessionFlf;
    type CtrlVlf = AeadCreateSessionVlf;
    const CREATE_SESSION:  ControlOpcode = ControlOpcode::AEAD_CREATE_SESSION;
    const DESTROY_SESSION: ControlOpcode = ControlOpcode::AEAD_DESTROY_SESSION;

    type DataFlf = AeadDataFlf;
    type DataVlfIn  = AeadDataVlfIn;
    type DataVlfOut = AeadDataVlfOut;

    type DataFlfStateless = AeadDataFlfStateless;
    type DataVlfStatelessIn  = AeadDataVlfStatelessIn;
    type DataVlfStatelessOut = AeadDataVlfStatelessOut;
}

#[derive(Debug)]
pub struct AkcipherSession;
impl CryptoSessionTrait for AkcipherSession {
    type CtrlFlf = AkcipherCreateSessionFlf;
    type CtrlVlf = AkcipherCreateSessionVlf;
    const CREATE_SESSION:  ControlOpcode = ControlOpcode::AKCIPHER_CREATE_SESSION;
    const DESTROY_SESSION: ControlOpcode = ControlOpcode::AKCIPHER_DESTROY_SESSION;

    type DataFlf = AkcipherDataFlf;
    type DataVlfIn  = AkcipherDataVlfIn;
    type DataVlfOut = AkcipherDataVlfOut;

    type DataFlfStateless = AkcipherDataFlfStateless;
    type DataVlfStatelessIn  = AkcipherDataVlfStatelessIn;
    type DataVlfStatelessOut = AkcipherDataVlfStatelessOut;
}

#[derive(Debug)]
pub struct CryptoSession<'a, T: CryptoSessionTrait> {
    device: &'a CryptoDevice,
    algo: u32,
    session_id: u64,
    _type_marker: PhantomData<T>,
}

impl<'a, T: CryptoSessionTrait> CryptoSession<'a, T> {
    pub fn new(device: &'a CryptoDevice, flf: &mut T::CtrlFlf, vlf: &T::CtrlVlf) 
        -> Result<Self, Status>
    {
        let algo = flf.get_algo();
        let header = ControlHeader {
            opcode: T::CREATE_SESSION as u32,
            algo,
            flag: 0, reserved: 0, //TODO: flag?
        };
        debug!("opcode: {:?}", T::CREATE_SESSION as u32);
        let session_info = create_session(&device.control_queue, &header, flf, vlf);
        debug!("sessino_info: {:?}", session_info);
        let status = session_info.get_status();
        match status {
            Status::OK => Result::Ok(Self {
                device,
                algo,
                session_id: session_info.session_id,
                _type_marker: PhantomData {},
            }),
            _ => Result::Err(status),
        }
    }

    pub fn basic_request(&self, opcode: u32, flf: &mut T::DataFlf, vlf_in: &T::DataVlfIn)
        -> Result<T::DataVlfOut, Status>
    {
        let header = DataHeader {
            opcode,
            algo: self.algo,
            session_id: self.session_id,
            flag: SessionMode::SESSION,
            padding: 0,
        };
        let request_info = 
            session_request(&self.device.data_queue, &header, flf, vlf_in);
        let status = request_info.1.get_status();
        match status {
            Status::OK => Result::Ok(request_info.0),
            _ => Result::Err(status),
        }
    }

    pub fn basic_request_stateless(&self, opcode: u32, flf: &mut T::DataFlfStateless, vlf_in: &T::DataVlfStatelessIn)
        -> Result<T::DataVlfStatelessOut, Status>
    {
        let header = DataHeader {
            opcode,
            algo: self.algo,
            session_id: self.session_id,
            flag: SessionMode::STATELESS,
            padding: 0,
        };
        let request_info = 
            session_request(&self.device.data_queue, &header, flf, vlf_in);
        let status = request_info.1.get_status();
        match status {
            Status::OK => Result::Ok(request_info.0),
            _ => Result::Err(status),
        }
    }

    pub fn destroy(self) -> Result<(), (Self, Status)> {
        let header = ControlHeader {
            opcode: T::DESTROY_SESSION as u32,
            algo: self.algo,
            flag: 0, reserved: 0, //TODO: flag?
        };
        let destroy_info = destroy_session(
            &self.device.control_queue, &header, self.session_id
        );
        let status = destroy_info.get_status();
        match status {
            Status::OK => Result::Ok(()),
            _ => Result::Err((self, status)),
        }
    }
}

fn new_dma(len: usize, init: bool, mut func: impl FnMut(VmWriter<Infallible>)) -> DmaStreamSlice<DmaStream> {
    let page_cnt = (len-1) / PAGE_SIZE + 1;
    let vm_segment = FrameAllocOptions::new(page_cnt).alloc_contiguous().unwrap();
    let stream = DmaStream::map(vm_segment, DmaDirection::Bidirectional, false).unwrap();
    if init {
        let writer = stream.writer().unwrap();
        func(writer);
    }
    DmaStreamSlice::new(stream, 0, PAGE_SIZE * page_cnt)
}

fn vlf_write_into_dma<T, U: VarLenFields<T>>(writer: &mut VmWriter<Infallible>, vlf: &U) {
    vlf.iter_over(|v| {
        writer.write(&mut VmReader::from(v.as_ref()));
    });
}

fn request_by_bytes(queue: &SpinLock<VirtQueue>, in_dma:DmaStreamSlice<DmaStream>, out_bytes: &mut [u8]) -> usize {
    let mut queue = queue.disable_irq().lock();

    let out_dma = new_dma(out_bytes.len(), false, |_|{});
    let token = queue
        .add_dma_buf(&[&in_dma], &[&out_dma])
        .expect("add queue failed");
    if queue.should_notify() {
        queue.notify();
    }
    let mut can_pop = false;
    for _ in 0..10000000 {
        spin_loop();
        if queue.can_pop() {
            can_pop = true;
            break;
        }
    }
    assert!(can_pop);

    queue.pop_used_with_token(token).expect("pop used failed");
    out_dma.sync().expect("sync failed");
    out_dma.reader().expect("get reader error").read(&mut VmWriter::from(out_bytes))
}


fn create_session<T: Pod>(control_queue: &SpinLock<VirtQueue>, header: &ControlHeader, flf: &mut T, vlf: &impl VarLenFields<T>) -> CreateSessionInput {
    vlf.fill_lengths(flf);
    let in_dma = new_dma(size_of_val(&header) + 56 + vlf.len(), true, // TODO: padding?
    |mut writer| {
        writer.write(&mut VmReader::from(header.as_bytes()));
        writer.write(&mut VmReader::from(flf.as_bytes()));
        writer = writer.skip(56 - size_of_val(flf));
        vlf_write_into_dma(&mut writer, vlf);
    });

    let out_len = size_of::<CreateSessionInput>();
    let mut out_bytes = vec![0 as u8; out_len].into_boxed_slice();
    request_by_bytes(control_queue, in_dma, &mut out_bytes);

    CreateSessionInput::from_bytes(out_bytes.as_ref())
}


fn destroy_session(control_queue: &SpinLock<VirtQueue>, header: &ControlHeader, session_id: u64) -> DestroySessionInput {
    let flf = DestroySessionFlf {
        session_id,
    };
    let in_dma = new_dma(size_of_val(&header) + size_of_val(&flf), true, // TODO: padding?
    |mut writer| {
        writer.write(&mut VmReader::from(header.as_bytes()));
        writer.write(&mut VmReader::from(flf.as_bytes()));
    });

    let out_len = size_of::<DestroySessionInput>();
    let mut out_bytes = vec![0 as u8; out_len].into_boxed_slice();
    request_by_bytes(control_queue, in_dma, &mut out_bytes);

    DestroySessionInput::from_bytes(out_bytes.as_ref())
}


fn session_request<T: Pod, VlfOut: VarLenFields<T>>(data_queue: &SpinLock<VirtQueue>, header: &DataHeader, flf: &mut T, vlf_in: &impl VarLenFields<T>)
    -> (VlfOut, CryptoInhdr)
{
    vlf_in.fill_lengths(flf);
    let in_dma = new_dma(size_of_val(header) + 48 + vlf_in.len(), true, // TODO: padding?
    |mut writer| {
        writer.write(&mut VmReader::from(header.as_bytes()));
        writer.write(&mut VmReader::from(flf.as_bytes()));
        writer = writer.skip(48 - size_of_val(flf));
        vlf_write_into_dma(&mut writer, vlf_in);
    });

    let vlf_out_len = VlfOut::len_from_packet(flf);
    let out_len = vlf_out_len + size_of::<CryptoInhdr>();
    //TODO: there might be a better way that read directly from DMA
    let mut out_bytes = vec![0 as u8; out_len].into_boxed_slice();
    request_by_bytes(data_queue, in_dma, &mut out_bytes);
    (
        VlfOut::from_bytes(out_bytes.as_ref(), &flf),
        CryptoInhdr::from_bytes(&out_bytes.as_ref()[vlf_out_len..])
    )
}