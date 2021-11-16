use netlink_packet_core::DecodeError;
use netlink_packet_utils::{
    nla::{DefaultNla, Nla, NlaBuffer},
    Parseable,
};

pub const NFULA_PACKET_HDR: u16 = libc::NFULA_PACKET_HDR as u16;
pub const NFULA_MARK: u16 = libc::NFULA_MARK as u16;
pub const NFULA_TIMESTAMP: u16 = libc::NFULA_TIMESTAMP as u16;
pub const NFULA_IFINDEX_INDEV: u16 = libc::NFULA_IFINDEX_INDEV as u16;
pub const NFULA_IFINDEX_OUTDEV: u16 = libc::NFULA_IFINDEX_OUTDEV as u16;
pub const NFULA_IFINDEX_PHYSINDEV: u16 = libc::NFULA_IFINDEX_PHYSINDEV as u16;
pub const NFULA_IFINDEX_PHYSOUTDEV: u16 = libc::NFULA_IFINDEX_PHYSOUTDEV as u16;
pub const NFULA_HWADDR: u16 = libc::NFULA_HWADDR as u16;
pub const NFULA_PAYLOAD: u16 = libc::NFULA_PAYLOAD as u16;
pub const NFULA_PREFIX: u16 = libc::NFULA_PREFIX as u16;
pub const NFULA_UID: u16 = libc::NFULA_UID as u16;
pub const NFULA_SEQ: u16 = libc::NFULA_SEQ as u16;
pub const NFULA_SEQ_GLOBAL: u16 = libc::NFULA_SEQ_GLOBAL as u16;
pub const NFULA_GID: u16 = libc::NFULA_GID as u16;
pub const NFULA_HWTYPE: u16 = libc::NFULA_HWTYPE as u16;
pub const NFULA_HWHEADER: u16 = libc::NFULA_HWHEADER as u16;
pub const NFULA_HWLEN: u16 = libc::NFULA_HWLEN as u16;
pub const NFULA_CT: u16 = libc::NFULA_CT as u16;
pub const NFULA_CT_INFO: u16 = libc::NFULA_CT_INFO as u16;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PacketNlas {
    Payload(Vec<u8>),
    Other(DefaultNla),
}

impl Nla for PacketNlas {
    fn value_len(&self) -> usize {
        match self {
            PacketNlas::Payload(vec) => vec.len(),
            PacketNlas::Other(ref attr) => attr.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            PacketNlas::Payload(_) => NFULA_PAYLOAD,
            PacketNlas::Other(ref attr) => attr.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            PacketNlas::Payload(vec) => buffer.copy_from_slice(vec),
            PacketNlas::Other(ref attr) => attr.emit_value(buffer),
        }
    }
}

impl<'buffer, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'buffer T>> for PacketNlas {
    fn parse(buf: &NlaBuffer<&'buffer T>) -> Result<Self, DecodeError> {
        let kind = buf.kind();
        let payload = buf.value();
        let nla = match kind {
            NFULA_PAYLOAD => PacketNlas::Payload(payload.to_vec()),
            _ => PacketNlas::Other(DefaultNla::parse(buf)?),
        };
        Ok(nla)
    }
}
