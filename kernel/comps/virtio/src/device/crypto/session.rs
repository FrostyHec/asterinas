use core::{hint::spin_loop, marker::PhantomData};

use alloc::vec;
use aster_block::request_queue;
use ostd::{mm::{DmaDirection, DmaStream, DmaStreamSlice, FrameAllocOptions, Infallible, VmReader, VmWriter, PAGE_SIZE}, sync::SpinLock, Pod};

use crate::queue::VirtQueue;

use super::{device::CryptoDevice, header::{self, *}};

trait CryptoSessionTrait: Sized {
    type Ctrl: ControlFlf;
    type Data: DataFlf;
    type DataStateless: DataFlf;
}

struct CryptoSession<'a, T: CryptoSessionTrait> {
    device: &'a CryptoDevice,
    algo: u32,
    session_id: u64,
    _type_marker: PhantomData<T>,
}

impl<'a, T: CryptoSessionTrait> CryptoSession<'a, T> {
    pub fn new(device: &'a CryptoDevice, flf: &mut T::Ctrl, vlf: &<T::Ctrl as ControlFlf>::Vlf) 
        -> Result<Self, Status>
    {
        let session_info = create_session(&device.control_queue, flf, vlf);
        let status = session_info.get_status();
        match status {
            Status::OK => Result::Ok(Self {
                device,
                algo: flf.get_algo(),
                session_id: session_info.session_id,
                _type_marker: PhantomData {},
            }),
            _ => Result::Err(status),
        }
    }

    fn basic_request(&self, opcode: u32, flf: &mut T::Data, vlf_in: &<T::Data as DataFlf>::VlfIn)
        -> Result<<T::Data as DataFlf>::VlfOut, Status>
    {
        let header = DataHeader {
            opcode,
            algo: self.algo,
            session_id: self.session_id,
            flag: 1, // TODO: I don't realy understand what it means
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

    fn basic_request_stateless(&self, opcode: u32, flf: &mut T::DataStateless, vlf_in: &<T::DataStateless as DataFlf>::VlfIn)
        -> Result<<T::DataStateless as DataFlf>::VlfOut, Status>
    {
        let header = DataHeader {
            opcode,
            algo: self.algo,
            session_id: self.session_id,
            flag: 0, // TODO: I don't realy understand what it means
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
        let destroy_info = destroy_session::<T::Ctrl>(
            &self.device.control_queue, self.algo, self.session_id
        );
        let status = destroy_info.get_status();
        match status {
            Status::OK => Result::Ok(()),
            _ => Result::Err((self, status)),
        }
    }
}

fn new_dma(len: usize, init: bool, mut func: impl FnMut(VmWriter<Infallible>)) -> DmaStreamSlice<DmaStream> {
    let vm_segment = FrameAllocOptions::new((len-1) / PAGE_SIZE + 1).alloc_contiguous().unwrap();
    let stream = DmaStream::map(vm_segment, DmaDirection::Bidirectional, false).unwrap();
    if init {
        let writer = stream.writer().unwrap();
        func(writer);
    }
    DmaStreamSlice::new(stream, 0, len)
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
    while !queue.can_pop() {
        spin_loop();
    }

    queue.pop_used_with_token(token).expect("pop used failed");
    out_dma.sync().expect("sync failed");
    out_dma.reader().expect("get reader error").read(&mut VmWriter::from(out_bytes))
}


fn create_session<T: ControlFlf>(control_queue: &SpinLock<VirtQueue>, flf: &mut T, vlf: &T::Vlf) -> CreateSessionInput {
    let header = ControlHeader {
        opcode: T::CREATE_SESSION as u32,
        algo: flf.get_algo(),
        flag: 0, reserved: 0, //TODO: flag?
    };
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


fn destroy_session<T: ControlFlf>(control_queue: &SpinLock<VirtQueue>, algo: u32, session_id: u64) -> DestroySessionInput {
    let header = ControlHeader {
        opcode: T::DESTROY_SESSION as u32,
        algo,
        flag: 0, reserved: 0, //TODO: flag?
    };
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


fn session_request<T: DataFlf>(data_queue: &SpinLock<VirtQueue>, header: &DataHeader, flf: &mut T, vlf_in: &T::VlfIn)
    -> (T::VlfOut, CryptoInhdr) 
{
    vlf_in.fill_lengths(flf);
    let in_dma = new_dma(size_of_val(header) + 48 + vlf_in.len(), true, // TODO: padding?
    |mut writer| {
        writer.write(&mut VmReader::from(header.as_bytes()));
        writer.write(&mut VmReader::from(flf.as_bytes()));
        writer = writer.skip(48 - size_of_val(flf));
        vlf_write_into_dma(&mut writer, vlf_in);
    });

    let vlf_out_len = T::VlfOut::len_from_packet(flf);
    let out_len = vlf_out_len + size_of::<CryptoInhdr>();
    let mut out_bytes = vec![0 as u8; out_len].into_boxed_slice();
    request_by_bytes(data_queue, in_dma, &mut out_bytes);
    (
        T::VlfOut::from_bytes(out_bytes.as_ref(), &flf),
        CryptoInhdr::from_bytes(&out_bytes.as_ref()[vlf_out_len..])
    )
}