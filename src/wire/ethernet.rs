use byteorder::{ByteOrder, NetworkEndian};
use core::fmt;

use super::{Error, Result};

enum_with_unknown! {
    /// 以太网协议类型枚举
    /// 
    /// 定义以太网帧中承载的上层协议类型，如IPv4、ARP、IPv6等
    pub enum EtherType(u16) {
        Ipv4 = 0x0800,
        Arp  = 0x0806,
        Ipv6 = 0x86DD
    }
}

impl fmt::Display for EtherType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            EtherType::Ipv4 => write!(f, "IPv4"),
            EtherType::Ipv6 => write!(f, "IPv6"),
            EtherType::Arp => write!(f, "ARP"),
            EtherType::Unknown(id) => write!(f, "0x{id:04x}"),
        }
    }
}

/// 以太网II型地址（6字节）
/// 
/// 表示48位的以太网MAC地址，用于数据链路层的设备标识
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Default)]
pub struct Address(pub [u8; 6]);

impl Address {
    /// 广播地址常量
    /// 
    /// 全FF的MAC地址，用于向同一网络中的所有设备发送数据
    pub const BROADCAST: Address = Address([0xff; 6]);

    /// 从大端字节序列构造以太网地址
    ///
    /// # 异常
    /// 如果`data`长度不是6字节，函数会panic
    pub fn from_bytes(data: &[u8]) -> Address {
        let mut bytes = [0; 6];
        bytes.copy_from_slice(data);
        Address(bytes)
    }

    /// 返回以太网地址的字节序列，大端格式
    /// 
    /// 将MAC地址转换为6字节的数组引用
    pub const fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// 查询地址是否为单播地址
    /// 
    /// 单播地址用于标识单个网络接口，既不是广播地址也不是多播地址
    pub fn is_unicast(&self) -> bool {
        !(self.is_broadcast() || self.is_multicast())
    }

    /// 查询此地址是否为广播地址
    /// 
    /// 广播地址是特殊的MAC地址，用于向网络中所有设备发送数据
    pub fn is_broadcast(&self) -> bool {
        *self == Self::BROADCAST
    }

    /// 查询OUI中的"多播"位是否设置
    /// 
    /// 多播位是MAC地址第一个字节的最低位，用于标识多播地址
    pub const fn is_multicast(&self) -> bool {
        self.0[0] & 0x01 != 0
    }

    /// 查询OUI中的"本地管理"位是否设置
    /// 
    /// 本地管理位是MAC地址第一个字节的倒数第二位，用于标识本地分配的地址
    pub const fn is_local(&self) -> bool {
        self.0[0] & 0x02 != 0
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let bytes = self.0;
        write!(
            f,
            "{:02x}-{:02x}-{:02x}-{:02x}-{:02x}-{:02x}",
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
        )
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for Address {
    fn format(&self, fmt: defmt::Formatter) {
        let bytes = self.0;
        defmt::write!(
            fmt,
            "{:02x}-{:02x}-{:02x}-{:02x}-{:02x}-{:02x}",
            bytes[0],
            bytes[1],
            bytes[2],
            bytes[3],
            bytes[4],
            bytes[5]
        )
    }
}

/// 以太网II型帧缓冲区的读写包装器
/// 
/// 提供对以太网帧的安全访问和操作，包括源地址、目的地址和协议类型
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Frame<T: AsRef<[u8]>> {
    buffer: T,
}

mod field {
    use crate::wire::field::*;

    pub const DESTINATION: Field = 0..6;
    pub const SOURCE: Field = 6..12;
    pub const ETHERTYPE: Field = 12..14;
    pub const PAYLOAD: Rest = 14..;
}

/// The Ethernet header length
pub const HEADER_LEN: usize = field::PAYLOAD.start;

impl<T: AsRef<[u8]>> Frame<T> {
    /// 将原始字节缓冲区赋予以太网帧结构
    /// 
    /// 创建一个新的以太网帧实例，不检查缓冲区长度和有效性
    pub const fn new_unchecked(buffer: T) -> Frame<T> {
        Frame { buffer }
    }

    /// [new_unchecked]和[check_len]的组合简写
    ///
    /// 先创建帧实例，然后检查长度有效性
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    pub fn new_checked(buffer: T) -> Result<Frame<T>> {
        let packet = Self::new_unchecked(buffer);
        packet.check_len()?;
        Ok(packet)
    }

    /// 确保调用访问器方法时不会panic
    /// 
    /// 如果缓冲区太短，返回`Err(Error)`
    pub fn check_len(&self) -> Result<()> {
        let len = self.buffer.as_ref().len();
        if len < HEADER_LEN { Err(Error) } else { Ok(()) }
    }

    /// 消费帧，返回底层缓冲区
    /// 
    /// 获取原始缓冲区数据，释放帧包装器
    pub fn into_inner(self) -> T {
        self.buffer
    }

    /// 返回帧头的长度
    /// 
    /// 以太网帧头固定为14字节（6字节目的地址 + 6字节源地址 + 2字节协议类型）
    pub const fn header_len() -> usize {
        HEADER_LEN
    }

    /// 返回持有给定长度负载的数据包所需的缓冲区长度
    /// 
    /// 计算包括帧头和负载在内的总缓冲区大小
    pub const fn buffer_len(payload_len: usize) -> usize {
        HEADER_LEN + payload_len
    }

    /// 返回目的地址字段
    /// 
    /// 获取以太网帧的目标MAC地址
    #[inline]
    pub fn dst_addr(&self) -> Address {
        let data = self.buffer.as_ref();
        Address::from_bytes(&data[field::DESTINATION])
    }

    /// 返回源地址字段
    /// 
    /// 获取以太网帧的源MAC地址
    #[inline]
    pub fn src_addr(&self) -> Address {
        let data = self.buffer.as_ref();
        Address::from_bytes(&data[field::SOURCE])
    }

    /// 返回以太网类型字段，不检查802.1Q
    /// 
    /// 获取帧中承载的上层协议类型，如IPv4、ARP、IPv6等
    #[inline]
    pub fn ethertype(&self) -> EtherType {
        let data = self.buffer.as_ref();
        let raw = NetworkEndian::read_u16(&data[field::ETHERTYPE]);
        EtherType::from(raw)
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Frame<&'a T> {
    /// 返回负载指针，不检查802.1Q
    /// 
    /// 获取以太网帧中上层协议数据的引用
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        let data = self.buffer.as_ref();
        &data[field::PAYLOAD]
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Frame<T> {
    /// 设置目的地址字段
    /// 
    /// 修改以太网帧的目标MAC地址
    #[inline]
    pub fn set_dst_addr(&mut self, value: Address) {
        let data = self.buffer.as_mut();
        data[field::DESTINATION].copy_from_slice(value.as_bytes())
    }

    /// 设置源地址字段
    /// 
    /// 修改以太网帧的源MAC地址
    #[inline]
    pub fn set_src_addr(&mut self, value: Address) {
        let data = self.buffer.as_mut();
        data[field::SOURCE].copy_from_slice(value.as_bytes())
    }

    /// 设置以太网类型字段
    /// 
    /// 修改帧中承载的上层协议类型
    #[inline]
    pub fn set_ethertype(&mut self, value: EtherType) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::ETHERTYPE], value.into())
    }

    /// 返回负载的可变指针
    /// 
    /// 获取以太网帧中上层协议数据的可变引用
    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let data = self.buffer.as_mut();
        &mut data[field::PAYLOAD]
    }
}

impl<T: AsRef<[u8]>> AsRef<[u8]> for Frame<T> {
    fn as_ref(&self) -> &[u8] {
        self.buffer.as_ref()
    }
}

impl<T: AsRef<[u8]>> fmt::Display for Frame<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "EthernetII src={} dst={} type={}",
            self.src_addr(),
            self.dst_addr(),
            self.ethertype()
        )
    }
}

use crate::wire::pretty_print::{PrettyIndent, PrettyPrint};

impl<T: AsRef<[u8]>> PrettyPrint for Frame<T> {
    fn pretty_print(
        buffer: &dyn AsRef<[u8]>,
        f: &mut fmt::Formatter,
        indent: &mut PrettyIndent,
    ) -> fmt::Result {
        let frame = match Frame::new_checked(buffer) {
            Err(err) => return write!(f, "{indent}({err})"),
            Ok(frame) => frame,
        };
        write!(f, "{indent}{frame}")?;

        match frame.ethertype() {
            #[cfg(feature = "proto-ipv4")]
            EtherType::Arp => {
                indent.increase(f)?;
                super::ArpPacket::<&[u8]>::pretty_print(&frame.payload(), f, indent)
            }
            #[cfg(feature = "proto-ipv4")]
            EtherType::Ipv4 => {
                indent.increase(f)?;
                super::Ipv4Packet::<&[u8]>::pretty_print(&frame.payload(), f, indent)
            }
            #[cfg(feature = "proto-ipv6")]
            EtherType::Ipv6 => {
                indent.increase(f)?;
                super::Ipv6Packet::<&[u8]>::pretty_print(&frame.payload(), f, indent)
            }
            _ => Ok(()),
        }
    }
}

/// 以太网II型帧的高级表示
/// 
/// 包含源MAC地址、目的MAC地址和以太网类型
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Repr {
    pub src_addr: Address,
    pub dst_addr: Address,
    pub ethertype: EtherType,
}

impl Repr {
    /// 解析以太网II型帧并返回高级表示
    /// 
    /// 从原始帧数据中提取源地址、目的地址和协议类型
    pub fn parse<T: AsRef<[u8]> + ?Sized>(frame: &Frame<&T>) -> Result<Repr> {
        frame.check_len()?;
        Ok(Repr {
            src_addr: frame.src_addr(),
            dst_addr: frame.dst_addr(),
            ethertype: frame.ethertype(),
        })
    }

    /// 返回从此高级表示发出的头部长度
    /// 
    /// 获取以太网帧头的字节数（固定为14字节）
    pub const fn buffer_len(&self) -> usize {
        HEADER_LEN
    }

    /// 将高级表示发出到以太网II型帧
    /// 
    /// 根据高级表示构建完整的以太网帧数据
    pub fn emit<T: AsRef<[u8]> + AsMut<[u8]>>(&self, frame: &mut Frame<T>) {
        assert!(frame.buffer.as_ref().len() >= self.buffer_len());
        frame.set_src_addr(self.src_addr);
        frame.set_dst_addr(self.dst_addr);
        frame.set_ethertype(self.ethertype);
    }
}

#[cfg(test)]
mod test {
    // Tests that are valid with any combination of
    // "proto-*" features.
    use super::*;

    #[test]
    fn test_broadcast() {
        assert!(Address::BROADCAST.is_broadcast());
        assert!(!Address::BROADCAST.is_unicast());
        assert!(Address::BROADCAST.is_multicast());
        assert!(Address::BROADCAST.is_local());
    }
}

#[cfg(test)]
#[cfg(feature = "proto-ipv4")]
mod test_ipv4 {
    // Tests that are valid only with "proto-ipv4"
    use super::*;

    static FRAME_BYTES: [u8; 64] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x08, 0x00, 0xaa,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0xff,
    ];

    static PAYLOAD_BYTES: [u8; 50] = [
        0xaa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xff,
    ];

    #[test]
    fn test_deconstruct() {
        let frame = Frame::new_unchecked(&FRAME_BYTES[..]);
        assert_eq!(
            frame.dst_addr(),
            Address([0x01, 0x02, 0x03, 0x04, 0x05, 0x06])
        );
        assert_eq!(
            frame.src_addr(),
            Address([0x11, 0x12, 0x13, 0x14, 0x15, 0x16])
        );
        assert_eq!(frame.ethertype(), EtherType::Ipv4);
        assert_eq!(frame.payload(), &PAYLOAD_BYTES[..]);
    }

    #[test]
    fn test_construct() {
        let mut bytes = vec![0xa5; 64];
        let mut frame = Frame::new_unchecked(&mut bytes);
        frame.set_dst_addr(Address([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]));
        frame.set_src_addr(Address([0x11, 0x12, 0x13, 0x14, 0x15, 0x16]));
        frame.set_ethertype(EtherType::Ipv4);
        frame.payload_mut().copy_from_slice(&PAYLOAD_BYTES[..]);
        assert_eq!(&frame.into_inner()[..], &FRAME_BYTES[..]);
    }
}

#[cfg(test)]
#[cfg(feature = "proto-ipv6")]
mod test_ipv6 {
    // Tests that are valid only with "proto-ipv6"
    use super::*;

    static FRAME_BYTES: [u8; 54] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x86, 0xdd, 0x60,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    ];

    static PAYLOAD_BYTES: [u8; 40] = [
        0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    ];

    #[test]
    fn test_deconstruct() {
        let frame = Frame::new_unchecked(&FRAME_BYTES[..]);
        assert_eq!(
            frame.dst_addr(),
            Address([0x01, 0x02, 0x03, 0x04, 0x05, 0x06])
        );
        assert_eq!(
            frame.src_addr(),
            Address([0x11, 0x12, 0x13, 0x14, 0x15, 0x16])
        );
        assert_eq!(frame.ethertype(), EtherType::Ipv6);
        assert_eq!(frame.payload(), &PAYLOAD_BYTES[..]);
    }

    #[test]
    fn test_construct() {
        let mut bytes = vec![0xa5; 54];
        let mut frame = Frame::new_unchecked(&mut bytes);
        frame.set_dst_addr(Address([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]));
        frame.set_src_addr(Address([0x11, 0x12, 0x13, 0x14, 0x15, 0x16]));
        frame.set_ethertype(EtherType::Ipv6);
        assert_eq!(PAYLOAD_BYTES.len(), frame.payload_mut().len());
        frame.payload_mut().copy_from_slice(&PAYLOAD_BYTES[..]);
        assert_eq!(&frame.into_inner()[..], &FRAME_BYTES[..]);
    }
}
