use core::convert::From;
use core::fmt;

use super::{Error, Result};
use crate::phy::ChecksumCapabilities;
#[cfg(feature = "proto-ipv4")]
use crate::wire::{Ipv4Address, Ipv4AddressExt, Ipv4Cidr, Ipv4Packet, Ipv4Repr};
#[cfg(feature = "proto-ipv6")]
use crate::wire::{Ipv6Address, Ipv6AddressExt, Ipv6Cidr, Ipv6Packet, Ipv6Repr};

/// IP协议版本枚举
/// 
/// 表示互联网协议的版本类型，支持IPv4和IPv6
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Version {
    #[cfg(feature = "proto-ipv4")]
    Ipv4,
    #[cfg(feature = "proto-ipv6")]
    Ipv6,
}

impl Version {
    /// 返回存储在提供缓冲区中的IP协议版本
    ///
    /// 该函数从不返回 `Ok(IpVersion::Unspecified)`；相反，未知版本会返回 `Err(Error)`
    pub const fn of_packet(data: &[u8]) -> Result<Version> {
        match data[0] >> 4 {
            #[cfg(feature = "proto-ipv4")]
            4 => Ok(Version::Ipv4),
            #[cfg(feature = "proto-ipv6")]
            6 => Ok(Version::Ipv6),
            _ => Err(Error),
        }
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            #[cfg(feature = "proto-ipv4")]
            Version::Ipv4 => write!(f, "IPv4"),
            #[cfg(feature = "proto-ipv6")]
            Version::Ipv6 => write!(f, "IPv6"),
        }
    }
}

enum_with_unknown! {
    /// IP数据报封装的协议类型枚举
    /// 
    /// 定义了IP层可以承载的上层协议类型，如ICMP、TCP、UDP等
    pub enum Protocol(u8) {
        HopByHop  = 0x00,
        Icmp      = 0x01,
        Igmp      = 0x02,
        Tcp       = 0x06,
        Udp       = 0x11,
        Ipv6Route = 0x2b,
        Ipv6Frag  = 0x2c,
        IpSecEsp  = 0x32,
        IpSecAh   = 0x33,
        Icmpv6    = 0x3a,
        Ipv6NoNxt = 0x3b,
        Ipv6Opts  = 0x3c
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Protocol::HopByHop => write!(f, "Hop-by-Hop"),
            Protocol::Icmp => write!(f, "ICMP"),
            Protocol::Igmp => write!(f, "IGMP"),
            Protocol::Tcp => write!(f, "TCP"),
            Protocol::Udp => write!(f, "UDP"),
            Protocol::Ipv6Route => write!(f, "IPv6-Route"),
            Protocol::Ipv6Frag => write!(f, "IPv6-Frag"),
            Protocol::IpSecEsp => write!(f, "IPsec-ESP"),
            Protocol::IpSecAh => write!(f, "IPsec-AH"),
            Protocol::Icmpv6 => write!(f, "ICMPv6"),
            Protocol::Ipv6NoNxt => write!(f, "IPv6-NoNxt"),
            Protocol::Ipv6Opts => write!(f, "IPv6-Opts"),
            Protocol::Unknown(id) => write!(f, "0x{id:02x}"),
        }
    }
}

/// 互联网地址枚举
/// 
/// 表示IP地址，支持IPv4和IPv6两种格式
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub enum Address {
    /// An IPv4 address.
    #[cfg(feature = "proto-ipv4")]
    Ipv4(Ipv4Address),
    /// An IPv6 address.
    #[cfg(feature = "proto-ipv6")]
    Ipv6(Ipv6Address),
}

impl Address {
    /// 使用给定的4个字节创建IPv4地址
    /// 
    /// 参数a0-a3分别对应IPv4地址的4个8位段
    #[cfg(feature = "proto-ipv4")]
    pub const fn v4(a0: u8, a1: u8, a2: u8, a3: u8) -> Address {
        Address::Ipv4(Ipv4Address::new(a0, a1, a2, a3))
    }

    /// 使用给定的8个16位段创建IPv6地址
    /// 
    /// 参数a0-a7分别对应IPv6地址的8个16位段
    #[cfg(feature = "proto-ipv6")]
    #[allow(clippy::too_many_arguments)]
    pub const fn v6(
        a0: u16,
        a1: u16,
        a2: u16,
        a3: u16,
        a4: u16,
        a5: u16,
        a6: u16,
        a7: u16,
    ) -> Address {
        Address::Ipv6(Ipv6Address::new(a0, a1, a2, a3, a4, a5, a6, a7))
    }

    /// 返回协议版本
    /// 
    /// 根据地址类型返回IPv4或IPv6版本信息
    pub const fn version(&self) -> Version {
        match self {
            #[cfg(feature = "proto-ipv4")]
            Address::Ipv4(_) => Version::Ipv4,
            #[cfg(feature = "proto-ipv6")]
            Address::Ipv6(_) => Version::Ipv6,
        }
    }

    /// 查询地址是否为有效的单播地址
    /// 
    /// 单播地址用于标识网络中的单个主机，与多播和广播地址区分
    pub fn is_unicast(&self) -> bool {
        match self {
            #[cfg(feature = "proto-ipv4")]
            Address::Ipv4(addr) => addr.x_is_unicast(),
            #[cfg(feature = "proto-ipv6")]
            Address::Ipv6(addr) => addr.x_is_unicast(),
        }
    }

    /// 查询地址是否为有效的多播地址
    /// 
    /// 多播地址用于标识一组主机，允许同时向多个目的地发送数据
    pub const fn is_multicast(&self) -> bool {
        match self {
            #[cfg(feature = "proto-ipv4")]
            Address::Ipv4(addr) => addr.is_multicast(),
            #[cfg(feature = "proto-ipv6")]
            Address::Ipv6(addr) => addr.is_multicast(),
        }
    }

    /// 查询地址是否为广播地址
    /// 
    /// 广播地址用于向网络中的所有主机发送数据，仅IPv4支持广播
    pub fn is_broadcast(&self) -> bool {
        match self {
            #[cfg(feature = "proto-ipv4")]
            Address::Ipv4(addr) => addr.is_broadcast(),
            #[cfg(feature = "proto-ipv6")]
            Address::Ipv6(_) => false,
        }
    }

    /// 查询地址是否属于"未指定"范围
    /// 
    /// 未指定地址（如IPv4的0.0.0.0或IPv6的::）通常用于表示地址未知或未分配
    pub fn is_unspecified(&self) -> bool {
        match self {
            #[cfg(feature = "proto-ipv4")]
            Address::Ipv4(addr) => addr.is_unspecified(),
            #[cfg(feature = "proto-ipv6")]
            Address::Ipv6(addr) => addr.is_unspecified(),
        }
    }

    /// 如果`self`是CIDR兼容的子网掩码，返回`Some(prefix_len)`
    /// 
    /// 其中`prefix_len`是前导零的数量，否则返回`None`
    /// 
    /// 用于判断地址是否可以作为有效的子网掩码
    pub fn prefix_len(&self) -> Option<u8> {
        match self {
            #[cfg(feature = "proto-ipv4")]
            Address::Ipv4(addr) => addr.prefix_len(),
            #[cfg(feature = "proto-ipv6")]
            Address::Ipv6(addr) => addr.prefix_len(),
        }
    }
}

#[cfg(all(feature = "proto-ipv4", feature = "proto-ipv6"))]
impl From<::core::net::IpAddr> for Address {
    fn from(x: ::core::net::IpAddr) -> Address {
        match x {
            ::core::net::IpAddr::V4(ipv4) => Address::Ipv4(ipv4),
            ::core::net::IpAddr::V6(ipv6) => Address::Ipv6(ipv6),
        }
    }
}

impl From<Address> for ::core::net::IpAddr {
    fn from(x: Address) -> ::core::net::IpAddr {
        match x {
            #[cfg(feature = "proto-ipv4")]
            Address::Ipv4(ipv4) => ::core::net::IpAddr::V4(ipv4),
            #[cfg(feature = "proto-ipv6")]
            Address::Ipv6(ipv6) => ::core::net::IpAddr::V6(ipv6),
        }
    }
}

#[cfg(feature = "proto-ipv4")]
impl From<Ipv4Address> for Address {
    fn from(ipv4: Ipv4Address) -> Address {
        Address::Ipv4(ipv4)
    }
}

#[cfg(feature = "proto-ipv6")]
impl From<Ipv6Address> for Address {
    fn from(addr: Ipv6Address) -> Self {
        Address::Ipv6(addr)
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            #[cfg(feature = "proto-ipv4")]
            Address::Ipv4(addr) => write!(f, "{addr}"),
            #[cfg(feature = "proto-ipv6")]
            Address::Ipv6(addr) => write!(f, "{addr}"),
        }
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for Address {
    fn format(&self, f: defmt::Formatter) {
        match self {
            #[cfg(feature = "proto-ipv4")]
            &Address::Ipv4(addr) => defmt::write!(f, "{:?}", addr),
            #[cfg(feature = "proto-ipv6")]
            &Address::Ipv6(addr) => defmt::write!(f, "{:?}", addr),
        }
    }
}

/// CIDR块规范，包含地址和可变长子网掩码前缀长度
/// 
/// 用于表示IP地址范围和子网划分
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub enum Cidr {
    #[cfg(feature = "proto-ipv4")]
    Ipv4(Ipv4Cidr),
    #[cfg(feature = "proto-ipv6")]
    Ipv6(Ipv6Cidr),
}

impl Cidr {
    /// 从给定地址和前缀长度创建CIDR块
    /// 
    /// 如果给定前缀长度对给定地址无效，此函数会panic
    pub const fn new(addr: Address, prefix_len: u8) -> Cidr {
        match addr {
            #[cfg(feature = "proto-ipv4")]
            Address::Ipv4(addr) => Cidr::Ipv4(Ipv4Cidr::new(addr, prefix_len)),
            #[cfg(feature = "proto-ipv6")]
            Address::Ipv6(addr) => Cidr::Ipv6(Ipv6Cidr::new(addr, prefix_len)),
        }
    }

    /// 返回此CIDR块的IP地址
    /// 
    /// 获取CIDR网络地址部分
    pub const fn address(&self) -> Address {
        match *self {
            #[cfg(feature = "proto-ipv4")]
            Cidr::Ipv4(cidr) => Address::Ipv4(cidr.address()),
            #[cfg(feature = "proto-ipv6")]
            Cidr::Ipv6(cidr) => Address::Ipv6(cidr.address()),
        }
    }

    /// 返回此CIDR块的前缀长度
    /// 
    /// 获取CIDR网络掩码位数
    pub const fn prefix_len(&self) -> u8 {
        match *self {
            #[cfg(feature = "proto-ipv4")]
            Cidr::Ipv4(cidr) => cidr.prefix_len(),
            #[cfg(feature = "proto-ipv6")]
            Cidr::Ipv6(cidr) => cidr.prefix_len(),
        }
    }

    /// 查询此CIDR块描述的子网是否包含给定地址
    /// 
    /// 判断指定IP地址是否属于此CIDR网络范围
    pub fn contains_addr(&self, addr: &Address) -> bool {
        match (self, addr) {
            #[cfg(feature = "proto-ipv4")]
            (Cidr::Ipv4(cidr), Address::Ipv4(addr)) => cidr.contains_addr(addr),
            #[cfg(feature = "proto-ipv6")]
            (Cidr::Ipv6(cidr), Address::Ipv6(addr)) => cidr.contains_addr(addr),
            #[allow(unreachable_patterns)]
            _ => false,
        }
    }

    /// 查询此CIDR块描述的子网是否包含给定CIDR块描述的子网
    /// 
    /// 判断一个子网是否完全包含在另一个子网内
    pub fn contains_subnet(&self, subnet: &Cidr) -> bool {
        match (self, subnet) {
            #[cfg(feature = "proto-ipv4")]
            (Cidr::Ipv4(cidr), Cidr::Ipv4(other)) => cidr.contains_subnet(other),
            #[cfg(feature = "proto-ipv6")]
            (Cidr::Ipv6(cidr), Cidr::Ipv6(other)) => cidr.contains_subnet(other),
            #[allow(unreachable_patterns)]
            _ => false,
        }
    }
}

#[cfg(feature = "proto-ipv4")]
impl From<Ipv4Cidr> for Cidr {
    fn from(addr: Ipv4Cidr) -> Self {
        Cidr::Ipv4(addr)
    }
}

#[cfg(feature = "proto-ipv6")]
impl From<Ipv6Cidr> for Cidr {
    fn from(addr: Ipv6Cidr) -> Self {
        Cidr::Ipv6(addr)
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            #[cfg(feature = "proto-ipv4")]
            Cidr::Ipv4(cidr) => write!(f, "{cidr}"),
            #[cfg(feature = "proto-ipv6")]
            Cidr::Ipv6(cidr) => write!(f, "{cidr}"),
        }
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for Cidr {
    fn format(&self, f: defmt::Formatter) {
        match self {
            #[cfg(feature = "proto-ipv4")]
            &Cidr::Ipv4(cidr) => defmt::write!(f, "{:?}", cidr),
            #[cfg(feature = "proto-ipv6")]
            &Cidr::Ipv6(cidr) => defmt::write!(f, "{:?}", cidr),
        }
    }
}

/// 互联网端点地址
/// 
/// `Endpoint`始终完全指定地址和端口
/// 
/// 另见['ListenEndpoint']，它允许不指定地址以便在任何地址上监听给定端口
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub struct Endpoint {
    pub addr: Address,
    pub port: u16,
}

impl Endpoint {
    /// 从给定地址和端口创建端点地址
    /// 
    /// 组合IP地址和端口号创建网络端点
    pub const fn new(addr: Address, port: u16) -> Endpoint {
        Endpoint { addr, port }
    }
}

#[cfg(all(feature = "proto-ipv4", feature = "proto-ipv6"))]
impl From<::core::net::SocketAddr> for Endpoint {
    fn from(x: ::core::net::SocketAddr) -> Endpoint {
        Endpoint {
            addr: x.ip().into(),
            port: x.port(),
        }
    }
}

#[cfg(feature = "proto-ipv4")]
impl From<::core::net::SocketAddrV4> for Endpoint {
    fn from(x: ::core::net::SocketAddrV4) -> Endpoint {
        Endpoint {
            addr: (*x.ip()).into(),
            port: x.port(),
        }
    }
}

#[cfg(feature = "proto-ipv6")]
impl From<::core::net::SocketAddrV6> for Endpoint {
    fn from(x: ::core::net::SocketAddrV6) -> Endpoint {
        Endpoint {
            addr: (*x.ip()).into(),
            port: x.port(),
        }
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}:{}", self.addr, self.port)
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for Endpoint {
    fn format(&self, f: defmt::Formatter) {
        defmt::write!(f, "{:?}:{=u16}", self.addr, self.port);
    }
}

impl<T: Into<Address>> From<(T, u16)> for Endpoint {
    fn from((addr, port): (T, u16)) -> Endpoint {
        Endpoint {
            addr: addr.into(),
            port,
        }
    }
}

/// An internet endpoint address for listening.
///
/// In contrast with [`Endpoint`], `ListenEndpoint` allows not specifying the address,
/// in order to listen on a given port at all our addresses.
///
/// An endpoint can be constructed from a port, in which case the address is unspecified.
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Default)]
pub struct ListenEndpoint {
    pub addr: Option<Address>,
    pub port: u16,
}

impl ListenEndpoint {
    /// Query whether the endpoint has a specified address and port.
    pub const fn is_specified(&self) -> bool {
        self.addr.is_some() && self.port != 0
    }
}

#[cfg(all(feature = "proto-ipv4", feature = "proto-ipv6"))]
impl From<::core::net::SocketAddr> for ListenEndpoint {
    fn from(x: ::core::net::SocketAddr) -> ListenEndpoint {
        ListenEndpoint {
            addr: Some(x.ip().into()),
            port: x.port(),
        }
    }
}

#[cfg(feature = "proto-ipv4")]
impl From<::core::net::SocketAddrV4> for ListenEndpoint {
    fn from(x: ::core::net::SocketAddrV4) -> ListenEndpoint {
        ListenEndpoint {
            addr: Some((*x.ip()).into()),
            port: x.port(),
        }
    }
}

#[cfg(feature = "proto-ipv6")]
impl From<::core::net::SocketAddrV6> for ListenEndpoint {
    fn from(x: ::core::net::SocketAddrV6) -> ListenEndpoint {
        ListenEndpoint {
            addr: Some((*x.ip()).into()),
            port: x.port(),
        }
    }
}

impl fmt::Display for ListenEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let Some(addr) = self.addr {
            write!(f, "{}:{}", addr, self.port)
        } else {
            write!(f, "*:{}", self.port)
        }
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for ListenEndpoint {
    fn format(&self, f: defmt::Formatter) {
        defmt::write!(f, "{:?}:{=u16}", self.addr, self.port);
    }
}

impl From<u16> for ListenEndpoint {
    fn from(port: u16) -> ListenEndpoint {
        ListenEndpoint { addr: None, port }
    }
}

impl From<Endpoint> for ListenEndpoint {
    fn from(endpoint: Endpoint) -> ListenEndpoint {
        ListenEndpoint {
            addr: Some(endpoint.addr),
            port: endpoint.port,
        }
    }
}

impl<T: Into<Address>> From<(T, u16)> for ListenEndpoint {
    fn from((addr, port): (T, u16)) -> ListenEndpoint {
        ListenEndpoint {
            addr: Some(addr.into()),
            port,
        }
    }
}

/// An IP packet representation.
///
/// This enum abstracts the various versions of IP packets. It either contains an IPv4
/// or IPv6 concrete high-level representation.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Repr {
    #[cfg(feature = "proto-ipv4")]
    Ipv4(Ipv4Repr),
    #[cfg(feature = "proto-ipv6")]
    Ipv6(Ipv6Repr),
}

#[cfg(feature = "proto-ipv4")]
impl From<Ipv4Repr> for Repr {
    fn from(repr: Ipv4Repr) -> Repr {
        Repr::Ipv4(repr)
    }
}

#[cfg(feature = "proto-ipv6")]
impl From<Ipv6Repr> for Repr {
    fn from(repr: Ipv6Repr) -> Repr {
        Repr::Ipv6(repr)
    }
}

/// 通用互联网协议数据包缓冲区的读写包装器
/// 
/// 提供对IP数据包（IPv4或IPv6）的统一访问接口
#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Packet<T: AsRef<[u8]>> {
    buffer: T,
}

mod field {
    use crate::wire::field::*;
    // 4-bit version number
    pub const VER: Field = 0..1;
}

impl<T: AsRef<[u8]>> Packet<T> {
    /// 创建具有IP数据包结构的原始字节缓冲区
    /// 
    /// 此数据包结构可以是IPv4或IPv6
    pub const fn new_unchecked(buffer: T) -> Packet<T> {
        Packet { buffer }
    }

    /// [new_unchecked]和[check_len]的组合简写
    /// 
    /// 先创建数据包实例，然后检查长度有效性
    pub fn new_checked(buffer: T) -> Result<Packet<T>> {
        let packet = Self::new_unchecked(buffer);
        packet.check_len()?;
        Ok(packet)
    }

    /// 确保调用时读取版本字段不会panic
    /// 
    /// 如果缓冲区太短，返回`Err(Error)`
    pub fn check_len(&self) -> Result<()> {
        // Both IPv4 and IPv6 headers contain Internet Protocol version in the upper nibble of the
        // first packet byte
        if self.buffer.as_ref().len() < field::VER.end {
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

    /// 返回版本字段
    /// 
    /// 获取IP协议版本号（4或6）
    pub fn version(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::VER.start] >> 4
    }
}

impl Repr {
    /// 创建新的IpRepr，为源/目的地址选择正确的IP版本
    /// 
    /// 如果`src_addr`和`dst_addr`是不同IP版本，会panic
    pub fn new(
        src_addr: Address,
        dst_addr: Address,
        next_header: Protocol,
        payload_len: usize,
        hop_limit: u8,
    ) -> Self {
        match (src_addr, dst_addr) {
            #[cfg(feature = "proto-ipv4")]
            (Address::Ipv4(src_addr), Address::Ipv4(dst_addr)) => Self::Ipv4(Ipv4Repr {
                src_addr,
                dst_addr,
                next_header,
                payload_len,
                hop_limit,
            }),
            #[cfg(feature = "proto-ipv6")]
            (Address::Ipv6(src_addr), Address::Ipv6(dst_addr)) => Self::Ipv6(Ipv6Repr {
                src_addr,
                dst_addr,
                next_header,
                payload_len,
                hop_limit,
            }),
            #[allow(unreachable_patterns)]
            _ => panic!("IP version mismatch: src={src_addr:?} dst={dst_addr:?}"),
        }
    }

    /// 解析互联网协议数据包并返回包含IPv4或IPv6数据包的[IpRepr]
    /// 
    /// 委托解析到特定的互联网协议解析函数，包含[ChecksumCapabilities]处理IPv4解析
    /// 如果数据包不包含有效的IPv4或IPv6数据包，或者特定IP版本功能未启用，返回`Err(Error)`
    pub fn parse<T: AsRef<[u8]> + ?Sized>(
        packet: &Packet<&T>,
        checksum_caps: &ChecksumCapabilities,
    ) -> Result<Repr> {
        packet.check_len()?;
        match packet.version() {
            #[cfg(feature = "proto-ipv4")]
            4 => {
                let packet = Ipv4Packet::new_checked(packet.buffer)?;
                let ipv4_repr = Ipv4Repr::parse(&packet, checksum_caps)?;
                Ok(Repr::Ipv4(ipv4_repr))
            }
            #[cfg(feature = "proto-ipv6")]
            6 => {
                let packet = Ipv6Packet::new_checked(packet.buffer)?;
                let ipv6_repr = Ipv6Repr::parse(&packet)?;
                Ok(Repr::Ipv6(ipv6_repr))
            }
            _ => Err(Error),
        }
    }

    /// Return the protocol version.
    pub const fn version(&self) -> Version {
        match *self {
            #[cfg(feature = "proto-ipv4")]
            Repr::Ipv4(_) => Version::Ipv4,
            #[cfg(feature = "proto-ipv6")]
            Repr::Ipv6(_) => Version::Ipv6,
        }
    }

    /// Return the source address.
    pub const fn src_addr(&self) -> Address {
        match *self {
            #[cfg(feature = "proto-ipv4")]
            Repr::Ipv4(repr) => Address::Ipv4(repr.src_addr),
            #[cfg(feature = "proto-ipv6")]
            Repr::Ipv6(repr) => Address::Ipv6(repr.src_addr),
        }
    }

    /// 返回目的地址
    /// 
    /// 获取目标IP地址
    pub const fn dst_addr(&self) -> Address {
        match *self {
            #[cfg(feature = "proto-ipv4")]
            Repr::Ipv4(repr) => Address::Ipv4(repr.dst_addr),
            #[cfg(feature = "proto-ipv6")]
            Repr::Ipv6(repr) => Address::Ipv6(repr.dst_addr),
        }
    }

    /// 返回下一头部（协议）
    /// 
    /// 获取上层协议类型（如TCP、UDP等）
    pub const fn next_header(&self) -> Protocol {
        match *self {
            #[cfg(feature = "proto-ipv4")]
            Repr::Ipv4(repr) => repr.next_header,
            #[cfg(feature = "proto-ipv6")]
            Repr::Ipv6(repr) => repr.next_header,
        }
    }

    /// 返回负载长度
    /// 
    /// 获取数据包负载部分的字节数
    pub const fn payload_len(&self) -> usize {
        match *self {
            #[cfg(feature = "proto-ipv4")]
            Repr::Ipv4(repr) => repr.payload_len,
            #[cfg(feature = "proto-ipv6")]
            Repr::Ipv6(repr) => repr.payload_len,
        }
    }

    /// 设置负载长度
    /// 
    /// 修改数据包负载部分的字节数
    pub fn set_payload_len(&mut self, length: usize) {
        match self {
            #[cfg(feature = "proto-ipv4")]
            Repr::Ipv4(Ipv4Repr { payload_len, .. }) => *payload_len = length,
            #[cfg(feature = "proto-ipv6")]
            Repr::Ipv6(Ipv6Repr { payload_len, .. }) => *payload_len = length,
        }
    }

    /// 返回TTL值
    /// 
    /// 获取生存时间（IPv4）或跳数限制（IPv6）
    pub const fn hop_limit(&self) -> u8 {
        match *self {
            #[cfg(feature = "proto-ipv4")]
            Repr::Ipv4(Ipv4Repr { hop_limit, .. }) => hop_limit,
            #[cfg(feature = "proto-ipv6")]
            Repr::Ipv6(Ipv6Repr { hop_limit, .. }) => hop_limit,
        }
    }

    /// 返回从此高级表示发出的头部长度
    /// 
    /// 获取IP头部占用的字节数
    pub const fn header_len(&self) -> usize {
        match *self {
            #[cfg(feature = "proto-ipv4")]
            Repr::Ipv4(repr) => repr.buffer_len(),
            #[cfg(feature = "proto-ipv6")]
            Repr::Ipv6(repr) => repr.buffer_len(),
        }
    }

    /// 将此高级表示发出到缓冲区
    /// 
    /// 将IP表示转换为字节序列并写入缓冲区
    pub fn emit<T: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        buffer: T,
        _checksum_caps: &ChecksumCapabilities,
    ) {
        match *self {
            #[cfg(feature = "proto-ipv4")]
            Repr::Ipv4(repr) => repr.emit(&mut Ipv4Packet::new_unchecked(buffer), _checksum_caps),
            #[cfg(feature = "proto-ipv6")]
            Repr::Ipv6(repr) => repr.emit(&mut Ipv6Packet::new_unchecked(buffer)),
        }
    }

    /// 返回从此高级表示发出的数据包总长度
    /// 
    /// 等同于`repr.buffer_len() + repr.payload_len()`
    pub const fn buffer_len(&self) -> usize {
        self.header_len() + self.payload_len()
    }
}

pub mod checksum {
    use byteorder::{ByteOrder, NetworkEndian};

    use super::*;

    const fn propagate_carries(word: u32) -> u16 {
        let sum = (word >> 16) + (word & 0xffff);
        ((sum >> 16) as u16) + (sum as u16)
    }

    /// 计算符合RFC 1071的校验和（不包含最终补码）
    /// 
    /// 用于IP、TCP、UDP等协议的校验和计算
    pub fn data(mut data: &[u8]) -> u16 {
        let mut accum = 0;

        // For each 32-byte chunk...
        const CHUNK_SIZE: usize = 32;
        while data.len() >= CHUNK_SIZE {
            let mut d = &data[..CHUNK_SIZE];
            // ... take by 2 bytes and sum them.
            while d.len() >= 2 {
                accum += NetworkEndian::read_u16(d) as u32;
                d = &d[2..];
            }

            data = &data[CHUNK_SIZE..];
        }

        // Sum the rest that does not fit the last 32-byte chunk,
        // taking by 2 bytes.
        while data.len() >= 2 {
            accum += NetworkEndian::read_u16(data) as u32;
            data = &data[2..];
        }

        // Add the last remaining odd byte, if any.
        if let Some(&value) = data.first() {
            accum += (value as u32) << 8;
        }

        propagate_carries(accum)
    }

    /// 组合多个符合RFC 1071的校验和
    /// 
    /// 将多个部分校验和合并为最终校验和
    pub fn combine(checksums: &[u16]) -> u16 {
        let mut accum: u32 = 0;
        for &word in checksums {
            accum += word as u32;
        }
        propagate_carries(accum)
    }

    #[cfg(feature = "proto-ipv4")]
    pub fn pseudo_header_v4(
        src_addr: &Ipv4Address,
        dst_addr: &Ipv4Address,
        next_header: Protocol,
        length: u32,
    ) -> u16 {
        let mut proto_len = [0u8; 4];
        proto_len[1] = next_header.into();
        NetworkEndian::write_u16(&mut proto_len[2..4], length as u16);

        combine(&[
            data(&src_addr.octets()),
            data(&dst_addr.octets()),
            data(&proto_len[..]),
        ])
    }

    #[cfg(feature = "proto-ipv6")]
    pub fn pseudo_header_v6(
        src_addr: &Ipv6Address,
        dst_addr: &Ipv6Address,
        next_header: Protocol,
        length: u32,
    ) -> u16 {
        let mut proto_len = [0u8; 4];
        proto_len[1] = next_header.into();
        NetworkEndian::write_u16(&mut proto_len[2..4], length as u16);

        combine(&[
            data(&src_addr.octets()),
            data(&dst_addr.octets()),
            data(&proto_len[..]),
        ])
    }

    pub fn pseudo_header(
        src_addr: &Address,
        dst_addr: &Address,
        next_header: Protocol,
        length: u32,
    ) -> u16 {
        match (src_addr, dst_addr) {
            #[cfg(feature = "proto-ipv4")]
            (Address::Ipv4(src_addr), Address::Ipv4(dst_addr)) => {
                pseudo_header_v4(src_addr, dst_addr, next_header, length)
            }
            #[cfg(feature = "proto-ipv6")]
            (Address::Ipv6(src_addr), Address::Ipv6(dst_addr)) => {
                pseudo_header_v6(src_addr, dst_addr, next_header, length)
            }
            #[allow(unreachable_patterns)]
            _ => unreachable!(),
        }
    }

    // We use this in pretty printer implementations.
    pub(crate) fn format_checksum(
        f: &mut fmt::Formatter,
        correct: bool,
        partially_correct: bool,
    ) -> fmt::Result {
        if !correct {
            if partially_correct {
                write!(f, " (partial checksum correct)")
            } else {
                write!(f, " (checksum incorrect)")
            }
        } else {
            Ok(())
        }
    }
}

use crate::wire::pretty_print::PrettyIndent;

pub fn pretty_print_ip_payload<T: Into<Repr>>(
    f: &mut fmt::Formatter,
    indent: &mut PrettyIndent,
    ip_repr: T,
    payload: &[u8],
) -> fmt::Result {
    #[cfg(feature = "proto-ipv4")]
    use super::pretty_print::PrettyPrint;
    #[cfg(feature = "proto-ipv4")]
    use crate::wire::Icmpv4Packet;
    use crate::wire::ip::checksum::format_checksum;
    use crate::wire::{TcpPacket, TcpRepr, UdpPacket, UdpRepr};

    let checksum_caps = ChecksumCapabilities::ignored();
    let repr = ip_repr.into();
    match repr.next_header() {
        #[cfg(feature = "proto-ipv4")]
        Protocol::Icmp => {
            indent.increase(f)?;
            Icmpv4Packet::<&[u8]>::pretty_print(&payload, f, indent)
        }
        Protocol::Udp => {
            indent.increase(f)?;
            match UdpPacket::<&[u8]>::new_checked(payload) {
                Err(err) => write!(f, "{indent}({err})"),
                Ok(udp_packet) => {
                    match UdpRepr::parse(
                        &udp_packet,
                        &repr.src_addr(),
                        &repr.dst_addr(),
                        &checksum_caps,
                    ) {
                        Err(err) => write!(f, "{indent}{udp_packet} ({err})"),
                        Ok(udp_repr) => {
                            write!(
                                f,
                                "{}{} len={}",
                                indent,
                                udp_repr,
                                udp_packet.payload().len()
                            )?;
                            let valid =
                                udp_packet.verify_checksum(&repr.src_addr(), &repr.dst_addr());
                            let partially_valid = udp_packet
                                .verify_partial_checksum(&repr.src_addr(), &repr.dst_addr());

                            format_checksum(f, valid, partially_valid)
                        }
                    }
                }
            }
        }
        Protocol::Tcp => {
            indent.increase(f)?;
            match TcpPacket::<&[u8]>::new_checked(payload) {
                Err(err) => write!(f, "{indent}({err})"),
                Ok(tcp_packet) => {
                    match TcpRepr::parse(
                        &tcp_packet,
                        &repr.src_addr(),
                        &repr.dst_addr(),
                        &checksum_caps,
                    ) {
                        Err(err) => write!(f, "{indent}{tcp_packet} ({err})"),
                        Ok(tcp_repr) => {
                            write!(f, "{indent}{tcp_repr}")?;
                            let valid =
                                tcp_packet.verify_checksum(&repr.src_addr(), &repr.dst_addr());
                            let partially_valid = tcp_packet
                                .verify_partial_checksum(&repr.src_addr(), &repr.dst_addr());

                            format_checksum(f, valid, partially_valid)
                        }
                    }
                }
            }
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
pub(crate) mod test {
    #![allow(unused)]

    use super::*;
    use crate::wire::{IpAddress, IpCidr, IpProtocol, IpRepr};
    #[cfg(feature = "proto-ipv4")]
    use crate::wire::{Ipv4Address, Ipv4Repr};

    #[test]
    #[cfg(feature = "proto-ipv4")]
    fn to_prefix_len_ipv4() {
        fn test_eq<A: Into<Address>>(prefix_len: u8, mask: A) {
            assert_eq!(Some(prefix_len), mask.into().prefix_len());
        }

        test_eq(0, Ipv4Address::new(0, 0, 0, 0));
        test_eq(1, Ipv4Address::new(128, 0, 0, 0));
        test_eq(2, Ipv4Address::new(192, 0, 0, 0));
        test_eq(3, Ipv4Address::new(224, 0, 0, 0));
        test_eq(4, Ipv4Address::new(240, 0, 0, 0));
        test_eq(5, Ipv4Address::new(248, 0, 0, 0));
        test_eq(6, Ipv4Address::new(252, 0, 0, 0));
        test_eq(7, Ipv4Address::new(254, 0, 0, 0));
        test_eq(8, Ipv4Address::new(255, 0, 0, 0));
        test_eq(9, Ipv4Address::new(255, 128, 0, 0));
        test_eq(10, Ipv4Address::new(255, 192, 0, 0));
        test_eq(11, Ipv4Address::new(255, 224, 0, 0));
        test_eq(12, Ipv4Address::new(255, 240, 0, 0));
        test_eq(13, Ipv4Address::new(255, 248, 0, 0));
        test_eq(14, Ipv4Address::new(255, 252, 0, 0));
        test_eq(15, Ipv4Address::new(255, 254, 0, 0));
        test_eq(16, Ipv4Address::new(255, 255, 0, 0));
        test_eq(17, Ipv4Address::new(255, 255, 128, 0));
        test_eq(18, Ipv4Address::new(255, 255, 192, 0));
        test_eq(19, Ipv4Address::new(255, 255, 224, 0));
        test_eq(20, Ipv4Address::new(255, 255, 240, 0));
        test_eq(21, Ipv4Address::new(255, 255, 248, 0));
        test_eq(22, Ipv4Address::new(255, 255, 252, 0));
        test_eq(23, Ipv4Address::new(255, 255, 254, 0));
        test_eq(24, Ipv4Address::new(255, 255, 255, 0));
        test_eq(25, Ipv4Address::new(255, 255, 255, 128));
        test_eq(26, Ipv4Address::new(255, 255, 255, 192));
        test_eq(27, Ipv4Address::new(255, 255, 255, 224));
        test_eq(28, Ipv4Address::new(255, 255, 255, 240));
        test_eq(29, Ipv4Address::new(255, 255, 255, 248));
        test_eq(30, Ipv4Address::new(255, 255, 255, 252));
        test_eq(31, Ipv4Address::new(255, 255, 255, 254));
        test_eq(32, Ipv4Address::new(255, 255, 255, 255));
    }

    #[test]
    #[cfg(feature = "proto-ipv4")]
    fn to_prefix_len_ipv4_error() {
        assert_eq!(
            None,
            IpAddress::from(Ipv4Address::new(255, 255, 255, 1)).prefix_len()
        );
    }

    #[test]
    #[cfg(feature = "proto-ipv6")]
    fn to_prefix_len_ipv6() {
        fn test_eq<A: Into<Address>>(prefix_len: u8, mask: A) {
            assert_eq!(Some(prefix_len), mask.into().prefix_len());
        }

        test_eq(0, Ipv6Address::new(0, 0, 0, 0, 0, 0, 0, 0));
        test_eq(
            128,
            Ipv6Address::new(
                0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
            ),
        );
    }

    #[test]
    #[cfg(feature = "proto-ipv6")]
    fn to_prefix_len_ipv6_error() {
        assert_eq!(
            None,
            IpAddress::from(Ipv6Address::new(
                0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0, 1
            ))
            .prefix_len()
        );
    }

    #[test]
    #[cfg(all(feature = "proto-ipv4", feature = "proto-ipv6"))]
    fn parse_ipv4_packet() {
        let ipv4_packet_bytes: [u8; 20] = [
            0x45, 0x00, 0x00, 0x14, 0x00, 0x01, 0x40, 0x00, 0x40, 0x01, 0xd2, 0x7c, 0x11, 0x12,
            0x13, 0x14, 0x21, 0x22, 0x23, 0x24,
        ];

        let expected = Ipv4Repr {
            src_addr: crate::wire::ipv4::Address::new(0x11, 0x12, 0x13, 0x14),
            dst_addr: crate::wire::ipv4::Address::new(0x21, 0x22, 0x23, 0x24),
            next_header: Protocol::Icmp,
            payload_len: 0,
            hop_limit: 64,
        };

        let packet = Packet::new_unchecked(&ipv4_packet_bytes[..]);
        let ip_repr = IpRepr::parse(&packet, &ChecksumCapabilities::default()).unwrap();
        assert_eq!(ip_repr.version(), Version::Ipv4);
        let IpRepr::Ipv4(ipv4_repr) = ip_repr else {
            panic!("expected Ipv4Repr");
        };
        assert_eq!(ipv4_repr, expected);
        assert_eq!(packet.into_inner(), ipv4_packet_bytes);
    }

    #[test]
    #[cfg(all(feature = "proto-ipv4", feature = "proto-ipv6"))]
    fn parse_ipv4_packet_error() {
        let ipv4_packet_bytes: [u8; 29] = [
            0x45, 0x00, 0x00, 0x1e, 0x01, 0x02, 0x62, 0x03, 0x1a, 0x01, 0xd5, 0x6e, 0x11, 0x12,
            0x13, 0x14, 0x21, 0x22, 0x23, 0x24, 0xaa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00,
        ];

        let packet = Packet::new_unchecked(&ipv4_packet_bytes[..]);
        let ip_repr_result = IpRepr::parse(&packet, &ChecksumCapabilities::default());
        assert!(ip_repr_result.is_err());
    }

    #[test]
    #[cfg(all(feature = "proto-ipv4", feature = "proto-ipv6"))]
    fn parse_ipv6_packet() {
        let ipv6_packet_bytes: [u8; 52] = [
            0x60, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x11, 0x40, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xff, 0x02, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01,
            0x00, 0x02, 0x00, 0x0c, 0x02, 0x4e, 0xff, 0xff, 0xff, 0xff,
        ];

        let expected = Ipv6Repr {
            src_addr: crate::wire::ipv6::Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
            dst_addr: crate::wire::ipv6::Address::new(0xff02, 0, 0, 0, 0, 0, 0, 1),
            next_header: Protocol::Udp,
            payload_len: 12,
            hop_limit: 64,
        };

        let packet = Packet::new_unchecked(&ipv6_packet_bytes[..]);
        let ip_repr = IpRepr::parse(&packet, &ChecksumCapabilities::default()).unwrap();
        assert_eq!(ip_repr.version(), Version::Ipv6);
        let IpRepr::Ipv6(ipv6_repr) = ip_repr else {
            panic!("expected Ipv6Repr");
        };
        assert_eq!(ipv6_repr, expected);
        assert_eq!(packet.into_inner(), ipv6_packet_bytes);
    }

    #[test]
    #[cfg(all(feature = "proto-ipv4", feature = "proto-ipv6"))]
    fn parse_ipv6_packet_error() {
        let ipv6_packet_bytes: [u8; 51] = [
            0x60, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x11, 0x40, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xff, 0x02, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01,
            0x00, 0x02, 0x00, 0x0c, 0x02, 0x4e, 0xff, 0xff, 0xff,
        ];

        let packet = Packet::new_unchecked(&ipv6_packet_bytes[..]);
        let ip_repr_result = IpRepr::parse(&packet, &ChecksumCapabilities::default());
        assert!(ip_repr_result.is_err());
    }

    #[test]
    #[cfg(all(feature = "proto-ipv4", feature = "proto-ipv6"))]
    fn parse_packet_too_short() {
        // Test empty packet where no version can be parsed
        let ip_packet = [0u8; 0];
        let packet_result = Packet::new_checked(&ip_packet[..]);
        assert!(packet_result.is_err());
    }

    #[test]
    #[cfg(all(feature = "proto-ipv4", feature = "proto-ipv6"))]
    fn parse_packet_invalid_version() {
        let packet_bytes: [u8; 1] = [0xFF];
        let packet = Packet::new_unchecked(&packet_bytes[..]);
        let ip_repr_result = IpRepr::parse(&packet, &ChecksumCapabilities::default());
        assert!(ip_repr_result.is_err());
    }
}
