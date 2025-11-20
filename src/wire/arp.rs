use byteorder::{ByteOrder, NetworkEndian};
use core::fmt;

use super::{Error, Result};
use super::{EthernetAddress, Ipv4Address, Ipv4AddressExt};

pub use super::EthernetProtocol as Protocol;

enum_with_unknown! {
    /// ARP硬件类型枚举
    /// 
    /// 定义ARP协议使用的硬件地址类型，如以太网
    pub enum Hardware(u16) {
        Ethernet = 1
    }
}

enum_with_unknown! {
    /// ARP操作类型枚举
    /// 
    /// 定义ARP协议的操作类型，包括请求和响应
    pub enum Operation(u16) {
        Request = 1,
        Reply = 2
    }
}

/// 地址解析协议(ARP)数据包缓冲区的读写包装器
/// 
/// 提供对ARP数据包的安全访问和操作，用于IP地址到MAC地址的解析
#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Packet<T: AsRef<[u8]>> {
    buffer: T,
}

mod field {
    #![allow(non_snake_case)]

    use crate::wire::field::*;

    pub const HTYPE: Field = 0..2;
    pub const PTYPE: Field = 2..4;
    pub const HLEN: usize = 4;
    pub const PLEN: usize = 5;
    pub const OPER: Field = 6..8;

    #[inline]
    pub const fn SHA(hardware_len: u8, _protocol_len: u8) -> Field {
        let start = OPER.end;
        start..(start + hardware_len as usize)
    }

    #[inline]
    pub const fn SPA(hardware_len: u8, protocol_len: u8) -> Field {
        let start = SHA(hardware_len, protocol_len).end;
        start..(start + protocol_len as usize)
    }

    #[inline]
    pub const fn THA(hardware_len: u8, protocol_len: u8) -> Field {
        let start = SPA(hardware_len, protocol_len).end;
        start..(start + hardware_len as usize)
    }

    #[inline]
    pub const fn TPA(hardware_len: u8, protocol_len: u8) -> Field {
        let start = THA(hardware_len, protocol_len).end;
        start..(start + protocol_len as usize)
    }
}

impl<T: AsRef<[u8]>> Packet<T> {
    /// 将原始字节缓冲区赋予ARP数据包结构
    /// 
    /// 创建ARP数据包实例，不检查缓冲区长度和有效性
    pub const fn new_unchecked(buffer: T) -> Packet<T> {
        Packet { buffer }
    }

    /// [new_unchecked]和[check_len]的组合简写
    ///
    /// 先创建数据包实例，然后检查长度有效性
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    pub fn new_checked(buffer: T) -> Result<Packet<T>> {
        let packet = Self::new_unchecked(buffer);
        packet.check_len()?;
        Ok(packet)
    }

    /// 确保调用访问器方法时不会panic
    /// 
    /// 如果缓冲区太短，返回`Err(Error)`
    ///
    /// 调用[set_hardware_len]或[set_protocol_len]会使此检查结果失效
    ///
    /// [set_hardware_len]: #method.set_hardware_len
    /// [set_protocol_len]: #method.set_protocol_len
    #[allow(clippy::if_same_then_else)]
    pub fn check_len(&self) -> Result<()> {
        let len = self.buffer.as_ref().len();
        if len < field::OPER.end {
            Err(Error)
        } else if len < field::TPA(self.hardware_len(), self.protocol_len()).end {
            Err(Error)
        } else {
            Ok(())
        }
    }

    /// 消费数据包，返回底层缓冲区
    /// 
    /// 获取原始缓冲区数据，释放数据包包装器
    pub fn into_inner(self) -> T {
        self.buffer
    }

    /// 返回硬件类型字段
    /// 
    /// 获取ARP协议使用的硬件地址类型，如以太网
    #[inline]
    pub fn hardware_type(&self) -> Hardware {
        let data = self.buffer.as_ref();
        let raw = NetworkEndian::read_u16(&data[field::HTYPE]);
        Hardware::from(raw)
    }

    /// 返回协议类型字段
    /// 
    /// 获取ARP协议解析的网络协议类型，通常是IPv4
    #[inline]
    pub fn protocol_type(&self) -> Protocol {
        let data = self.buffer.as_ref();
        let raw = NetworkEndian::read_u16(&data[field::PTYPE]);
        Protocol::from(raw)
    }

    /// 返回硬件地址长度字段
    /// 
    /// 获取硬件地址的字节长度，以太网为6字节
    #[inline]
    pub fn hardware_len(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::HLEN]
    }

    /// 返回协议地址长度字段
    /// 
    /// 获取网络协议地址的字节长度，IPv4为4字节
    #[inline]
    pub fn protocol_len(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::PLEN]
    }

    /// 返回操作字段
    /// 
    /// 获取ARP操作类型，如请求(1)或响应(2)
    #[inline]
    pub fn operation(&self) -> Operation {
        let data = self.buffer.as_ref();
        let raw = NetworkEndian::read_u16(&data[field::OPER]);
        Operation::from(raw)
    }

    /// 返回源硬件地址字段
    /// 
    /// 获取发送方的MAC地址
    pub fn source_hardware_addr(&self) -> &[u8] {
        let data = self.buffer.as_ref();
        &data[field::SHA(self.hardware_len(), self.protocol_len())]
    }

    /// 返回源协议地址字段
    /// 
    /// 获取发送方的IP地址
    pub fn source_protocol_addr(&self) -> &[u8] {
        let data = self.buffer.as_ref();
        &data[field::SPA(self.hardware_len(), self.protocol_len())]
    }

    /// 返回目的硬件地址字段
    /// 
    /// 获取接收方的MAC地址
    pub fn target_hardware_addr(&self) -> &[u8] {
        let data = self.buffer.as_ref();
        &data[field::THA(self.hardware_len(), self.protocol_len())]
    }

    /// 返回目的协议地址字段
    /// 
    /// 获取接收方的IP地址
    pub fn target_protocol_addr(&self) -> &[u8] {
        let data = self.buffer.as_ref();
        &data[field::TPA(self.hardware_len(), self.protocol_len())]
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    /// 设置硬件类型字段
    /// 
    /// 修改ARP协议使用的硬件地址类型
    #[inline]
    pub fn set_hardware_type(&mut self, value: Hardware) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::HTYPE], value.into())
    }

    /// 设置协议类型字段
    /// 
    /// 修改ARP协议解析的网络协议类型
    #[inline]
    pub fn set_protocol_type(&mut self, value: Protocol) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::PTYPE], value.into())
    }

    /// 设置硬件长度字段
    /// 
    /// 修改硬件地址的字节长度
    #[inline]
    pub fn set_hardware_len(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[field::HLEN] = value
    }

    /// 设置协议长度字段
    /// 
    /// 修改网络协议地址的字节长度
    #[inline]
    pub fn set_protocol_len(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[field::PLEN] = value
    }

    /// 设置操作字段
    /// 
    /// 修改ARP操作类型，如请求或响应
    #[inline]
    pub fn set_operation(&mut self, value: Operation) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::OPER], value.into())
    }

    /// 设置源硬件地址字段
    /// 
    /// 修改发送方的MAC地址
    ///
    /// # Panics
    /// The function panics if `value` is not `self.hardware_len()` long.
    pub fn set_source_hardware_addr(&mut self, value: &[u8]) {
        let (hardware_len, protocol_len) = (self.hardware_len(), self.protocol_len());
        let data = self.buffer.as_mut();
        data[field::SHA(hardware_len, protocol_len)].copy_from_slice(value)
    }

    /// 设置源协议地址字段
    /// 
    /// 修改发送方的IP地址
    ///
    /// # Panics
    /// The function panics if `value` is not `self.protocol_len()` long.
    pub fn set_source_protocol_addr(&mut self, value: &[u8]) {
        let (hardware_len, protocol_len) = (self.hardware_len(), self.protocol_len());
        let data = self.buffer.as_mut();
        data[field::SPA(hardware_len, protocol_len)].copy_from_slice(value)
    }

    /// 设置目的硬件地址字段
    /// 
    /// 修改接收方的MAC地址
    ///
    /// # Panics
    /// The function panics if `value` is not `self.hardware_len()` long.
    pub fn set_target_hardware_addr(&mut self, value: &[u8]) {
        let (hardware_len, protocol_len) = (self.hardware_len(), self.protocol_len());
        let data = self.buffer.as_mut();
        data[field::THA(hardware_len, protocol_len)].copy_from_slice(value)
    }

    /// 设置目的协议地址字段
    /// 
    /// 修改接收方的IP地址
    ///
    /// # Panics
    /// The function panics if `value` is not `self.protocol_len()` long.
    pub fn set_target_protocol_addr(&mut self, value: &[u8]) {
        let (hardware_len, protocol_len) = (self.hardware_len(), self.protocol_len());
        let data = self.buffer.as_mut();
        data[field::TPA(hardware_len, protocol_len)].copy_from_slice(value)
    }
}

impl<T: AsRef<[u8]>> AsRef<[u8]> for Packet<T> {
    fn as_ref(&self) -> &[u8] {
        self.buffer.as_ref()
    }
}

/// 地址解析协议数据包的高级表示
/// 
/// 包含ARP操作类型和地址信息，用于IP地址到MAC地址的映射
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[non_exhaustive]
pub enum Repr {
    /// An Ethernet and IPv4 Address Resolution Protocol packet.
    EthernetIpv4 {
        operation: Operation,
        source_hardware_addr: EthernetAddress,
        source_protocol_addr: Ipv4Address,
        target_hardware_addr: EthernetAddress,
        target_protocol_addr: Ipv4Address,
    },
}

impl Repr {
    /// 解析地址解析协议数据包并返回高级表示
    /// 
    /// 如果数据包不被识别，返回`Err(Error)`
    pub fn parse<T: AsRef<[u8]>>(packet: &Packet<T>) -> Result<Repr> {
        packet.check_len()?;

        match (
            packet.hardware_type(),
            packet.protocol_type(),
            packet.hardware_len(),
            packet.protocol_len(),
        ) {
            (Hardware::Ethernet, Protocol::Ipv4, 6, 4) => Ok(Repr::EthernetIpv4 {
                operation: packet.operation(),
                source_hardware_addr: EthernetAddress::from_bytes(packet.source_hardware_addr()),
                source_protocol_addr: Ipv4Address::from_bytes(packet.source_protocol_addr()),
                target_hardware_addr: EthernetAddress::from_bytes(packet.target_hardware_addr()),
                target_protocol_addr: Ipv4Address::from_bytes(packet.target_protocol_addr()),
            }),
            _ => Err(Error),
        }
    }

    /// 返回数据包长度
    /// 
    /// 计算ARP数据包的总字节数，包括所有字段
    pub const fn buffer_len(&self) -> usize {
        match *self {
            Repr::EthernetIpv4 { .. } => field::TPA(6, 4).end,
        }
    }

    /// 将高级表示发射到地址解析协议数据包
    /// 
    /// 根据高级表示生成ARP数据包内容
    pub fn emit<T: AsRef<[u8]> + AsMut<[u8]>>(&self, packet: &mut Packet<T>) {
        match *self {
            Repr::EthernetIpv4 {
                operation,
                source_hardware_addr,
                source_protocol_addr,
                target_hardware_addr,
                target_protocol_addr,
            } => {
                packet.set_hardware_type(Hardware::Ethernet);
                packet.set_protocol_type(Protocol::Ipv4);
                packet.set_hardware_len(6);
                packet.set_protocol_len(4);
                packet.set_operation(operation);
                packet.set_source_hardware_addr(source_hardware_addr.as_bytes());
                packet.set_source_protocol_addr(&source_protocol_addr.octets());
                packet.set_target_hardware_addr(target_hardware_addr.as_bytes());
                packet.set_target_protocol_addr(&target_protocol_addr.octets());
            }
        }
    }
}

impl<T: AsRef<[u8]>> fmt::Display for Packet<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match Repr::parse(self) {
            Ok(repr) => write!(f, "{repr}"),
            _ => {
                write!(f, "ARP (unrecognized)")?;
                write!(
                    f,
                    " htype={:?} ptype={:?} hlen={:?} plen={:?} op={:?}",
                    self.hardware_type(),
                    self.protocol_type(),
                    self.hardware_len(),
                    self.protocol_len(),
                    self.operation()
                )?;
                write!(
                    f,
                    " sha={:?} spa={:?} tha={:?} tpa={:?}",
                    self.source_hardware_addr(),
                    self.source_protocol_addr(),
                    self.target_hardware_addr(),
                    self.target_protocol_addr()
                )?;
                Ok(())
            }
        }
    }
}

impl fmt::Display for Repr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Repr::EthernetIpv4 {
                operation,
                source_hardware_addr,
                source_protocol_addr,
                target_hardware_addr,
                target_protocol_addr,
            } => {
                write!(
                    f,
                    "ARP type=Ethernet+IPv4 src={source_hardware_addr}/{source_protocol_addr} tgt={target_hardware_addr}/{target_protocol_addr} op={operation:?}"
                )
            }
        }
    }
}

use crate::wire::pretty_print::{PrettyIndent, PrettyPrint};

impl<T: AsRef<[u8]>> PrettyPrint for Packet<T> {
    fn pretty_print(
        buffer: &dyn AsRef<[u8]>,
        f: &mut fmt::Formatter,
        indent: &mut PrettyIndent,
    ) -> fmt::Result {
        match Packet::new_checked(buffer) {
            Err(err) => write!(f, "{indent}({err})"),
            Ok(packet) => write!(f, "{indent}{packet}"),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    static PACKET_BYTES: [u8; 28] = [
        0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x21,
        0x22, 0x23, 0x24, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x41, 0x42, 0x43, 0x44,
    ];

    #[test]
    fn test_deconstruct() {
        let packet = Packet::new_unchecked(&PACKET_BYTES[..]);
        assert_eq!(packet.hardware_type(), Hardware::Ethernet);
        assert_eq!(packet.protocol_type(), Protocol::Ipv4);
        assert_eq!(packet.hardware_len(), 6);
        assert_eq!(packet.protocol_len(), 4);
        assert_eq!(packet.operation(), Operation::Request);
        assert_eq!(
            packet.source_hardware_addr(),
            &[0x11, 0x12, 0x13, 0x14, 0x15, 0x16]
        );
        assert_eq!(packet.source_protocol_addr(), &[0x21, 0x22, 0x23, 0x24]);
        assert_eq!(
            packet.target_hardware_addr(),
            &[0x31, 0x32, 0x33, 0x34, 0x35, 0x36]
        );
        assert_eq!(packet.target_protocol_addr(), &[0x41, 0x42, 0x43, 0x44]);
    }

    #[test]
    fn test_construct() {
        let mut bytes = vec![0xa5; 28];
        let mut packet = Packet::new_unchecked(&mut bytes);
        packet.set_hardware_type(Hardware::Ethernet);
        packet.set_protocol_type(Protocol::Ipv4);
        packet.set_hardware_len(6);
        packet.set_protocol_len(4);
        packet.set_operation(Operation::Request);
        packet.set_source_hardware_addr(&[0x11, 0x12, 0x13, 0x14, 0x15, 0x16]);
        packet.set_source_protocol_addr(&[0x21, 0x22, 0x23, 0x24]);
        packet.set_target_hardware_addr(&[0x31, 0x32, 0x33, 0x34, 0x35, 0x36]);
        packet.set_target_protocol_addr(&[0x41, 0x42, 0x43, 0x44]);
        assert_eq!(&*packet.into_inner(), &PACKET_BYTES[..]);
    }

    fn packet_repr() -> Repr {
        Repr::EthernetIpv4 {
            operation: Operation::Request,
            source_hardware_addr: EthernetAddress::from_bytes(&[
                0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
            ]),
            source_protocol_addr: Ipv4Address::from_bytes(&[0x21, 0x22, 0x23, 0x24]),
            target_hardware_addr: EthernetAddress::from_bytes(&[
                0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
            ]),
            target_protocol_addr: Ipv4Address::from_bytes(&[0x41, 0x42, 0x43, 0x44]),
        }
    }

    #[test]
    fn test_parse() {
        let packet = Packet::new_unchecked(&PACKET_BYTES[..]);
        let repr = Repr::parse(&packet).unwrap();
        assert_eq!(repr, packet_repr());
    }

    #[test]
    fn test_emit() {
        let mut bytes = vec![0xa5; 28];
        let mut packet = Packet::new_unchecked(&mut bytes);
        packet_repr().emit(&mut packet);
        assert_eq!(&*packet.into_inner(), &PACKET_BYTES[..]);
    }
}
