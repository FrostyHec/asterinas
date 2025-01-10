use ostd::{mm::{DmaDirection, DmaStream, DmaStreamSlice, FrameAllocOptions, Infallible, VmReader, VmWriter, PAGE_SIZE}, Pod};

use super::header::*;

trait CryptoSession: Sized {
    fn new() -> Result<Self, ()>;
    fn get_session_id(&self) -> u64;
    fn destroy_session(self) -> Result<(), Self> {
        // TODO: ...
        let status = Status::OK;
        match status {
            Status::OK => Ok(()),
            _ => Err(self),
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

fn control_into_dma<T: ControlFlf>(flf: &mut T, vlf: &T::Vlf) -> (
    DmaStreamSlice<DmaStream>, 
    DmaStreamSlice<DmaStream>,
) {
    let header = ControlHeader {
        opcode: T::CREATE_SESSION as u32,
        algo: flf.get_algo(),
        flag: 0, reserved: 0, //TODO: flag?
    };
    vlf.fill_lengths(flf);
    (
        new_dma(size_of_val(&header) + 56 + vlf.len(), true, // TODO: padding?
        |mut writer| {
            writer.write(&mut VmReader::from(header.as_bytes()));
            writer.write(&mut VmReader::from(flf.as_bytes()));
            writer = writer.skip(56 - size_of_val(flf));
            vlf_write_into_dma(&mut writer, vlf);
        }),
        new_dma(size_of::<CreateSessionInput>(), false, |_|{})
    )
}

fn data_into_dma<T: DataFlf>(header: &DataHeader, flf: &mut T, vlf_in: &T::VlfIn, vlf_out: &T::VlfOut) -> (
    DmaStreamSlice<DmaStream>, 
    DmaStreamSlice<DmaStream>,
) {
    vlf_in .fill_lengths(flf);
    vlf_out.fill_lengths(flf);
    (
        new_dma(size_of_val(header) + 48 + vlf_in.len(), true,
        |mut writer| {
            writer.write(&mut VmReader::from(header.as_bytes()));
            writer.write(&mut VmReader::from(flf.as_bytes()));
            writer = writer.skip(48 - size_of_val(flf));
            vlf_write_into_dma(&mut writer, vlf_in);
        }),
        new_dma(vlf_out.len() + size_of::<CryptoInhdr>(), false, |_|{})
    )
}