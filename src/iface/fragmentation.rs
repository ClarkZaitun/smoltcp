#![allow(unused)]

use core::fmt;

use managed::{ManagedMap, ManagedSlice};

use crate::config::{FRAGMENTATION_BUFFER_SIZE, REASSEMBLY_BUFFER_COUNT, REASSEMBLY_BUFFER_SIZE};
use crate::storage::Assembler;
use crate::time::{Duration, Instant};
use crate::wire::*;

use core::result::Result;

#[cfg(feature = "alloc")]
type Buffer = alloc::vec::Vec<u8>;
#[cfg(not(feature = "alloc"))]
type Buffer = [u8; REASSEMBLY_BUFFER_SIZE];

/// Problem when assembling: something was out of bounds.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct AssemblerError;

impl fmt::Display for AssemblerError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "AssemblerError")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for AssemblerError {}

/// Packet assembler is full
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct AssemblerFullError;

impl fmt::Display for AssemblerFullError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "AssemblerFullError")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for AssemblerFullError {}

/// 数据包分片重组器
/// 用于存储和重组IP分片数据包的不同片段
///
/// `PacketAssembler`使用的缓冲区可以是动态大小的（如Vec<u8>）
/// 或者根据重组数据包的MTU静态分配（如IPv6帧为1280字节）
#[derive(Debug)]
pub struct PacketAssembler<K> {
    key: Option<K>,      // 重组键（通常包含源IP、目的IP、标识等）
    buffer: Buffer,    // 重组缓冲区

    assembler: Assembler,      // 分片偏移管理器
    total_size: Option<usize>, // 预期总大小
    expires_at: Instant,       // 过期时间
}

impl<K> PacketAssembler<K> {
    /// 创建新的空分片重组缓冲区
    /// 初始化所有字段为默认值，准备接收分片数据
    pub const fn new() -> Self {
        Self {
            key: None,

            #[cfg(feature = "alloc")]
            buffer: Buffer::new(),
            #[cfg(not(feature = "alloc"))]
            buffer: [0u8; REASSEMBLY_BUFFER_SIZE],

            assembler: Assembler::new(),
            total_size: None,
            expires_at: Instant::ZERO,
        }
    }

    pub(crate) fn reset(&mut self) {
        self.key = None;
        self.assembler.clear();
        self.total_size = None;
        self.expires_at = Instant::ZERO;
    }

    /// Set the total size of the packet assembler.
    pub(crate) fn set_total_size(&mut self, size: usize) -> Result<(), AssemblerError> {
        if let Some(old_size) = self.total_size {
            if old_size != size {
                return Err(AssemblerError);
            }
        }

        #[cfg(not(feature = "alloc"))]
        if self.buffer.len() < size {
            return Err(AssemblerError);
        }

        #[cfg(feature = "alloc")]
        if self.buffer.len() < size {
            self.buffer.resize(size, 0);
        }

        self.total_size = Some(size);
        Ok(())
    }

    /// Return the instant when the assembler expires.
    pub(crate) fn expires_at(&self) -> Instant {
        self.expires_at
    }

    pub(crate) fn add_with(
        &mut self,
        offset: usize,
        f: impl Fn(&mut [u8]) -> Result<usize, AssemblerError>,
    ) -> Result<(), AssemblerError> {
        if self.buffer.len() < offset {
            return Err(AssemblerError);
        }

        let len = f(&mut self.buffer[offset..])?;
        assert!(offset + len <= self.buffer.len());

        net_debug!(
            "frag assembler: receiving {} octets at offset {}",
            len,
            offset
        );

        self.assembler.add(offset, len);
        Ok(())
    }

    /// 添加分片到正在重组的数据包中
    ///
    /// # 参数
    /// * `data` - 分片数据
    /// * `offset` - 分片在原始数据包中的偏移位置
    ///
    /// # 错误
    /// - 当尝试在缓冲区不存在的位置添加数据时返回 [`Error::PacketAssemblerBufferTooSmall`]
    pub(crate) fn add(&mut self, data: &[u8], offset: usize) -> Result<(), AssemblerError> {
        #[cfg(not(feature = "alloc"))]
        if self.buffer.len() < offset + data.len() {
            return Err(AssemblerError);
        }

        #[cfg(feature = "alloc")]
        if self.buffer.len() < offset + data.len() {
            self.buffer.resize(offset + data.len(), 0);
        }

        let len = data.len();
        self.buffer[offset..][..len].copy_from_slice(data);

        net_debug!(
            "frag assembler: receiving {} octets at offset {}",
            len,
            offset
        );

        self.assembler.add(offset, data.len());
        Ok(())
    }

    /// 获取重组完成的完整数据包
    /// 如果重组完成，返回底层数据的不变切片，并重置重组器以便重用
    /// 如果重组未完成，返回None
    pub(crate) fn assemble(&mut self) -> Option<&'_ [u8]> {
        if !self.is_complete() {
            return None;
        }

        // NOTE: we can unwrap because `is_complete` already checks this.
        let total_size = self.total_size.unwrap();
        self.reset();
        Some(&self.buffer[..total_size])
    }

    /// 检查是否已接收所有分片
    /// 当所有分片都已接收且按正确顺序排列时返回true，否则返回false
    /// 通过比较预期总大小与已组装的数据大小来判断完整性
    pub(crate) fn is_complete(&self) -> bool {
        self.total_size == Some(self.assembler.peek_front())
    }

    /// Returns `true` when the packet assembler is free to use.
    fn is_free(&self) -> bool {
        self.key.is_none()
    }
}

/// 管理多个数据包重组器的集合
/// 用于同时处理多个不同数据流的分片重组
#[derive(Debug)]
pub struct PacketAssemblerSet<K: Eq + Copy> {
    assemblers: [PacketAssembler<K>; REASSEMBLY_BUFFER_COUNT],  // 重组器数组
}

impl<K: Eq + Copy> PacketAssemblerSet<K> {
    const NEW_PA: PacketAssembler<K> = PacketAssembler::new();

    /// 创建新的数据包重组器集合
    /// 初始化指定数量的重组器，用于并发处理多个数据流的分片
    pub fn new() -> Self {
        Self {
            assemblers: [Self::NEW_PA; REASSEMBLY_BUFFER_COUNT],
        }
    }

    /// Get a [`PacketAssembler`] for a specific key.
    ///
    /// If it doesn't exist, it is created, with the `expires_at` timestamp.
    ///
    /// If the assembler set is full, in which case an error is returned.
    pub(crate) fn get(
        &mut self,
        key: &K,
        expires_at: Instant,
    ) -> Result<&mut PacketAssembler<K>, AssemblerFullError> {
        let mut empty_slot = None;
        for slot in &mut self.assemblers {
            if slot.key.as_ref() == Some(key) {
                return Ok(slot);
            }
            if slot.is_free() {
                empty_slot = Some(slot)
            }
        }

        let slot = empty_slot.ok_or(AssemblerFullError)?;
        slot.key = Some(*key);
        slot.expires_at = expires_at;
        Ok(slot)
    }

    /// Remove all [`PacketAssembler`]s that are expired.
    pub fn remove_expired(&mut self, timestamp: Instant) {
        for frag in &mut self.assemblers {
            if !frag.is_free() && frag.expires_at < timestamp {
                frag.reset();
            }
        }
    }
}

// Max len of non-fragmented packets after decompression (including ipv6 header and payload)
// TODO: lower. Should be (6lowpan mtu) - (min 6lowpan header size) + (max ipv6 header size)
pub(crate) const MAX_DECOMPRESSED_LEN: usize = 1500;

#[cfg(feature = "_proto-fragmentation")]
#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(crate) enum FragKey {
    #[cfg(feature = "proto-ipv4-fragmentation")]
    Ipv4(Ipv4FragKey),
    #[cfg(feature = "proto-sixlowpan-fragmentation")]
    Sixlowpan(SixlowpanFragKey),
}

pub(crate) struct FragmentsBuffer {
    #[cfg(feature = "proto-sixlowpan")]
    pub decompress_buf: [u8; MAX_DECOMPRESSED_LEN],

    #[cfg(feature = "_proto-fragmentation")]
    pub assembler: PacketAssemblerSet<FragKey>,

    #[cfg(feature = "_proto-fragmentation")]
    pub reassembly_timeout: Duration,
}

#[cfg(not(feature = "_proto-fragmentation"))]
pub(crate) struct Fragmenter {}

#[cfg(not(feature = "_proto-fragmentation"))]
impl Fragmenter {
    pub(crate) fn new() -> Self {
        Self {}
    }
}

#[cfg(feature = "_proto-fragmentation")]
pub(crate) struct Fragmenter {
    /// The buffer that holds the unfragmented 6LoWPAN packet.
    pub buffer: [u8; FRAGMENTATION_BUFFER_SIZE],
    /// The size of the packet without the IEEE802.15.4 header and the fragmentation headers.
    pub packet_len: usize,
    /// The amount of bytes that already have been transmitted.
    pub sent_bytes: usize,

    #[cfg(feature = "proto-ipv4-fragmentation")]
    pub ipv4: Ipv4Fragmenter,
    #[cfg(feature = "proto-sixlowpan-fragmentation")]
    pub sixlowpan: SixlowpanFragmenter,
}

#[cfg(feature = "proto-ipv4-fragmentation")]
pub(crate) struct Ipv4Fragmenter {
    /// The IPv4 representation.
    pub repr: Ipv4Repr,
    /// The destination hardware address.
    #[cfg(feature = "medium-ethernet")]
    pub dst_hardware_addr: EthernetAddress,
    /// The offset of the next fragment.
    pub frag_offset: u16,
    /// The identifier of the stream.
    pub ident: u16,
}

#[cfg(feature = "proto-sixlowpan-fragmentation")]
pub(crate) struct SixlowpanFragmenter {
    /// The datagram size that is used for the fragmentation headers.
    pub datagram_size: u16,
    /// The datagram tag that is used for the fragmentation headers.
    pub datagram_tag: u16,
    pub datagram_offset: usize,

    /// The size of the FRAG_N packets.
    pub fragn_size: usize,

    /// The link layer IEEE802.15.4 source address.
    pub ll_dst_addr: Ieee802154Address,
    /// The link layer IEEE802.15.4 source address.
    pub ll_src_addr: Ieee802154Address,
}

#[cfg(feature = "_proto-fragmentation")]
impl Fragmenter {
    pub(crate) fn new() -> Self {
        Self {
            buffer: [0u8; FRAGMENTATION_BUFFER_SIZE],
            packet_len: 0,
            sent_bytes: 0,

            #[cfg(feature = "proto-ipv4-fragmentation")]
            ipv4: Ipv4Fragmenter {
                repr: Ipv4Repr {
                    src_addr: Ipv4Address::new(0, 0, 0, 0),
                    dst_addr: Ipv4Address::new(0, 0, 0, 0),
                    next_header: IpProtocol::Unknown(0),
                    payload_len: 0,
                    hop_limit: 0,
                },
                #[cfg(feature = "medium-ethernet")]
                dst_hardware_addr: EthernetAddress::default(),
                frag_offset: 0,
                ident: 0,
            },

            #[cfg(feature = "proto-sixlowpan-fragmentation")]
            sixlowpan: SixlowpanFragmenter {
                datagram_size: 0,
                datagram_tag: 0,
                datagram_offset: 0,
                fragn_size: 0,
                ll_dst_addr: Ieee802154Address::Absent,
                ll_src_addr: Ieee802154Address::Absent,
            },
        }
    }

    /// Return `true` when everything is transmitted.
    #[inline]
    pub(crate) fn finished(&self) -> bool {
        self.packet_len == self.sent_bytes
    }

    /// Returns `true` when there is nothing to transmit.
    #[inline]
    pub(crate) fn is_empty(&self) -> bool {
        self.packet_len == 0
    }

    // Reset the buffer.
    pub(crate) fn reset(&mut self) {
        self.packet_len = 0;
        self.sent_bytes = 0;

        #[cfg(feature = "proto-ipv4-fragmentation")]
        {
            self.ipv4.repr = Ipv4Repr {
                src_addr: Ipv4Address::new(0, 0, 0, 0),
                dst_addr: Ipv4Address::new(0, 0, 0, 0),
                next_header: IpProtocol::Unknown(0),
                payload_len: 0,
                hop_limit: 0,
            };
            #[cfg(feature = "medium-ethernet")]
            {
                self.ipv4.dst_hardware_addr = EthernetAddress::default();
            }
        }

        #[cfg(feature = "proto-sixlowpan-fragmentation")]
        {
            self.sixlowpan.datagram_size = 0;
            self.sixlowpan.datagram_tag = 0;
            self.sixlowpan.fragn_size = 0;
            self.sixlowpan.ll_dst_addr = Ieee802154Address::Absent;
            self.sixlowpan.ll_src_addr = Ieee802154Address::Absent;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
    struct Key {
        id: usize,
    }

    #[test]
    fn packet_assembler_overlap() {
        let mut p_assembler = PacketAssembler::<Key>::new();

        p_assembler.set_total_size(5).unwrap();

        let data = b"Rust";
        p_assembler.add(&data[..], 0);
        p_assembler.add(&data[..], 1);

        assert_eq!(p_assembler.assemble(), Some(&b"RRust"[..]))
    }

    #[test]
    fn packet_assembler_assemble() {
        let mut p_assembler = PacketAssembler::<Key>::new();

        let data = b"Hello World!";

        p_assembler.set_total_size(data.len()).unwrap();

        p_assembler.add(b"Hello ", 0).unwrap();
        assert_eq!(p_assembler.assemble(), None);

        p_assembler.add(b"World!", b"Hello ".len()).unwrap();

        assert_eq!(p_assembler.assemble(), Some(&b"Hello World!"[..]));
    }

    #[test]
    fn packet_assembler_out_of_order_assemble() {
        let mut p_assembler = PacketAssembler::<Key>::new();

        let data = b"Hello World!";

        p_assembler.set_total_size(data.len()).unwrap();

        p_assembler.add(b"World!", b"Hello ".len()).unwrap();
        assert_eq!(p_assembler.assemble(), None);

        p_assembler.add(b"Hello ", 0).unwrap();

        assert_eq!(p_assembler.assemble(), Some(&b"Hello World!"[..]));
    }

    #[test]
    fn packet_assembler_set() {
        let key = Key { id: 1 };

        let mut set = PacketAssemblerSet::new();

        assert!(set.get(&key, Instant::ZERO).is_ok());
    }

    #[test]
    fn packet_assembler_set_full() {
        let mut set = PacketAssemblerSet::new();
        for i in 0..REASSEMBLY_BUFFER_COUNT {
            set.get(&Key { id: i }, Instant::ZERO).unwrap();
        }
        assert!(set.get(&Key { id: 4 }, Instant::ZERO).is_err());
    }

    #[test]
    fn packet_assembler_set_assembling_many() {
        let mut set = PacketAssemblerSet::new();

        let key = Key { id: 0 };
        let assr = set.get(&key, Instant::ZERO).unwrap();
        assert_eq!(assr.assemble(), None);
        assr.set_total_size(0).unwrap();
        assr.assemble().unwrap();

        // Test that `.assemble()` effectively deletes it.
        let assr = set.get(&key, Instant::ZERO).unwrap();
        assert_eq!(assr.assemble(), None);
        assr.set_total_size(0).unwrap();
        assr.assemble().unwrap();

        let key = Key { id: 1 };
        let assr = set.get(&key, Instant::ZERO).unwrap();
        assr.set_total_size(0).unwrap();
        assr.assemble().unwrap();

        let key = Key { id: 2 };
        let assr = set.get(&key, Instant::ZERO).unwrap();
        assr.set_total_size(0).unwrap();
        assr.assemble().unwrap();

        let key = Key { id: 2 };
        let assr = set.get(&key, Instant::ZERO).unwrap();
        assr.set_total_size(2).unwrap();
        assr.add(&[0x00], 0).unwrap();
        assert_eq!(assr.assemble(), None);
        let assr = set.get(&key, Instant::ZERO).unwrap();
        assr.add(&[0x01], 1).unwrap();
        assert_eq!(assr.assemble(), Some(&[0x00, 0x01][..]));
    }
}
