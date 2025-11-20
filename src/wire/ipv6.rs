#![deny(missing_docs)]

use byteorder::{ByteOrder, NetworkEndian};
use core::fmt;

use super::{Error, Result};
use crate::wire::ip::pretty_print_ip_payload;

pub use super::IpProtocol as Protocol;

/// IPv6最小MTU（最大传输单元）要求，所有支持IPv6的链路都必须支持的最小数据包大小
/// 参考RFC 8200第5节：每个IPv6链路都必须能够传输至少1280字节的数据包
///
/// [RFC 8200 § 5]: https://tools.ietf.org/html/rfc8200#section-5
pub const MIN_MTU: usize = 1280;

/// IPv6地址的字节大小
///
/// [RFC 8200 § 2]: https://www.rfc-editor.org/rfc/rfc4291#section-2
pub const ADDR_SIZE: usize = 16;

/// 链路本地所有节点多播地址
///
/// 用于向链路本地范围内的所有节点发送多播消息
/// [all nodes multicast address]: https://tools.ietf.org/html/rfc4291#section-2.7.1
pub const LINK_LOCAL_ALL_NODES: Address = Address::new(0xff02, 0, 0, 0, 0, 0, 0, 1);

/// 链路本地所有路由器多播地址
///
/// 用于向链路本地范围内的所有路由器发送多播消息
/// [all routers multicast address]: https://tools.ietf.org/html/rfc4291#section-2.7.1
pub const LINK_LOCAL_ALL_ROUTERS: Address = Address::new(0xff02, 0, 0, 0, 0, 0, 0, 2);

/// 链路本地所有MLDv2能力路由器多播地址
///
/// 用于向支持MLDv2（多播监听发现协议版本2）的路由器发送多播消息
/// [all MLVDv2-capable routers multicast address]: https://tools.ietf.org/html/rfc3810#section-11
pub const LINK_LOCAL_ALL_MLDV2_ROUTERS: Address = Address::new(0xff02, 0, 0, 0, 0, 0, 0, 0x16);

/// 链路本地所有RPL节点多播地址
///
/// 用于向支持RPL（IPv6路由协议）的节点发送多播消息
/// [all RPL nodes multicast address]: https://www.rfc-editor.org/rfc/rfc6550.html#section-20.19
pub const LINK_LOCAL_ALL_RPL_NODES: Address = Address::new(0xff02, 0, 0, 0, 0, 0, 0, 0x1a);

/// IPv6多播地址的作用域
///
/// 定义了IPv6多播地址的有效范围，从本地接口到全球范围
/// [scope]: https://www.rfc-editor.org/rfc/rfc4291#section-2.7
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MulticastScope {
    /// 接口本地作用域 - 仅在本机内部有效
    InterfaceLocal = 0x1,
    /// 链路本地作用域 - 仅在本地链路有效
    LinkLocal = 0x2,
    /// 管理本地作用域 - 管理员配置的范围
    AdminLocal = 0x4,
    /// 站点本地作用域 - 单个站点范围内有效
    SiteLocal = 0x5,
    /// 组织本地作用域 - 整个组织范围内有效
    OrganizationLocal = 0x8,
    /// 全球作用域 - 全球互联网范围内有效
    Global = 0xE,
    /// 未知作用域 - 无法识别的范围
    Unknown = 0xFF,
}

impl From<u8> for MulticastScope {
    fn from(value: u8) -> Self {
        match value {
            0x1 => Self::InterfaceLocal,
            0x2 => Self::LinkLocal,
            0x4 => Self::AdminLocal,
            0x5 => Self::SiteLocal,
            0x8 => Self::OrganizationLocal,
            0xE => Self::Global,
            _ => Self::Unknown,
        }
    }
}

pub use core::net::Ipv6Addr as Address;

/// IPv6地址扩展trait
///
/// 提供IPv6地址相关的额外功能，包括地址类型判断、作用域查询等
pub(crate) trait AddressExt {
    /// 从大端字节序列构造IPv6地址
    ///
    /// # 异常
    /// 如果`data`长度不是16字节，函数会panic
    fn from_bytes(data: &[u8]) -> Address;

    /// 查询IPv6地址是否为单播地址
    ///
    /// 单播地址用于标识单个网络接口，与多播和任播地址区分
    /// [unicast address]: https://tools.ietf.org/html/rfc4291#section-2.5
    ///
    /// `x_`前缀用于避免与`core::ip`中不稳定的方法冲突
    fn x_is_unicast(&self) -> bool;

    /// 查询IPv6地址是否为全球单播地址
    ///
    /// 全球单播地址是在全球范围内唯一的地址，可用于互联网通信
    /// [global unicast address]: https://datatracker.ietf.org/doc/html/rfc3587
    fn is_global_unicast(&self) -> bool;

    /// 查询IPv6地址是否在链路本地作用域内
    ///
    /// 链路本地地址仅在本地链路范围内有效，不能路由到互联网
    /// [link-local]: https://tools.ietf.org/html/rfc4291#section-2.5.6
    fn is_link_local(&self) -> bool;

    /// 查询IPv6地址是否为唯一本地地址（ULA）
    ///
    /// ULA是在私有网络中使用的地址，类似于IPv4的私有地址
    /// [Unique Local Address]: https://tools.ietf.org/html/rfc4193
    ///
    /// `x_`前缀用于避免与`core::ip`中不稳定的方法冲突
    fn x_is_unique_local(&self) -> bool;

    /// 根据给定前缀掩码地址的辅助函数
    ///
    /// 返回掩码后的地址字节数组
    ///
    /// # 异常
    /// 如果`mask`大于128，函数会panic
    fn mask(&self, mask: u8) -> [u8; ADDR_SIZE];

    /// 返回给定单播地址的请求节点多播地址
    ///
    /// 请求节点多播地址用于邻居发现协议中的地址解析
    ///
    /// # 异常
    /// 如果给定地址不是单播地址，函数会panic
    fn solicited_node(&self) -> Address;

    /// 返回地址的作用域
    ///
    /// 根据地址类型返回其在网络中的作用范围
    /// `x_`前缀用于避免与`core::ip`中不稳定的方法冲突
    fn x_multicast_scope(&self) -> MulticastScope;

    /// 查询IPv6地址是否为请求节点多播地址
    ///
    /// 请求节点多播地址用于IPv6邻居发现协议
    /// [Solicited-node multicast address]: https://datatracker.ietf.org/doc/html/rfc4291#section-2.7.1
    fn is_solicited_node_multicast(&self) -> bool;

    /// 如果`self`是CIDR兼容的子网掩码，返回`Some(prefix_len)`
    /// 其中`prefix_len`是前导零的数量，否则返回`None`
    ///
    /// 用于判断地址是否可以作为有效的子网掩码
    fn prefix_len(&self) -> Option<u8>;
}

impl AddressExt for Address {
    fn from_bytes(data: &[u8]) -> Address {
        let mut bytes = [0; ADDR_SIZE];
        bytes.copy_from_slice(data);
        Address::from(bytes)
    }

    fn x_is_unicast(&self) -> bool {
        !(self.is_multicast() || self.is_unspecified())
    }

    fn is_global_unicast(&self) -> bool {
        (self.octets()[0] >> 5) == 0b001
    }

    fn is_link_local(&self) -> bool {
        self.octets()[0..8] == [0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    }

    fn x_is_unique_local(&self) -> bool {
        (self.octets()[0] & 0b1111_1110) == 0xfc
    }

    fn mask(&self, mask: u8) -> [u8; ADDR_SIZE] {
        assert!(mask <= 128);
        let mut bytes = [0u8; ADDR_SIZE];
        let idx = (mask as usize) / 8;
        let modulus = (mask as usize) % 8;
        let octets = self.octets();
        let (first, second) = octets.split_at(idx);
        bytes[0..idx].copy_from_slice(first);
        if idx < ADDR_SIZE {
            let part = second[0];
            bytes[idx] = part & (!(0xff >> modulus) as u8);
        }
        bytes
    }

    fn solicited_node(&self) -> Address {
        assert!(self.x_is_unicast());
        let o = self.octets();
        Address::from([
            0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xFF, o[13],
            o[14], o[15],
        ])
    }

    fn x_multicast_scope(&self) -> MulticastScope {
        if self.is_multicast() {
            return MulticastScope::from(self.octets()[1] & 0b1111);
        }

        if self.is_link_local() {
            MulticastScope::LinkLocal
        } else if self.x_is_unique_local() || self.is_global_unicast() {
            // ULA are considered global scope
            // https://www.rfc-editor.org/rfc/rfc6724#section-3.1
            MulticastScope::Global
        } else {
            MulticastScope::Unknown
        }
    }

    fn is_solicited_node_multicast(&self) -> bool {
        self.octets()[0..13]
            == [
                0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xFF,
            ]
    }

    fn prefix_len(&self) -> Option<u8> {
        let mut ones = true;
        let mut prefix_len = 0;
        for byte in self.octets() {
            let mut mask = 0x80;
            for _ in 0..8 {
                let one = byte & mask != 0;
                if ones {
                    // Expect 1s until first 0
                    if one {
                        prefix_len += 1;
                    } else {
                        ones = false;
                    }
                } else if one {
                    // 1 where 0 was expected
                    return None;
                }
                mask >>= 1;
            }
        }
        Some(prefix_len)
    }
}

/// IPv6 CIDR（无类域间路由）块规范，包含IP地址和可变长子网掩码前缀长度
///
/// CIDR表示法：IP地址/前缀长度，如2001:db8::/64
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub struct Cidr {
    address: Address,    // 网络地址
    prefix_len: u8,      // 前缀长度（0-128）
}

impl Cidr {
    /// 请求节点前缀
    ///
    /// 用于邻居发现协议中的请求节点多播地址
    /// [solicited node prefix]: https://tools.ietf.org/html/rfc4291#section-2.7.1
    pub const SOLICITED_NODE_PREFIX: Cidr = Cidr {
        address: Address::new(0xff02, 0, 0, 0, 0, 1, 0xff00, 0),
        prefix_len: 104,
    };

    /// 从给定地址和前缀长度创建IPv6 CIDR块
    ///
    /// # 异常
    /// 如果前缀长度大于128，函数会panic
    pub const fn new(address: Address, prefix_len: u8) -> Cidr {
        assert!(prefix_len <= 128);
        Cidr {
            address,
            prefix_len,
        }
    }

    /// 返回此IPv6 CIDR块的地址
    pub const fn address(&self) -> Address {
        self.address
    }

    /// 返回此IPv6 CIDR块的前缀长度
    pub const fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    /// 查询由此IPv6 CIDR块描述的子网是否包含给定地址
    ///
    /// 通过比较掩码后的地址来判断地址是否属于该子网
    pub fn contains_addr(&self, addr: &Address) -> bool {
        // 右移128位是非法的
        if self.prefix_len == 0 {
            return true;
        }

        self.address.mask(self.prefix_len) == addr.mask(self.prefix_len)
    }

    /// 查询由此IPv6 CIDR块描述的子网是否包含给定IPv6 CIDR块描述的子网
    ///
    /// 判断一个子网是否完全包含在另一个子网内
    pub fn contains_subnet(&self, subnet: &Cidr) -> bool {
        self.prefix_len <= subnet.prefix_len && self.contains_addr(&subnet.address)
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // https://tools.ietf.org/html/rfc4291#section-2.3
        write!(f, "{}/{}", self.address, self.prefix_len)
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for Cidr {
    fn format(&self, f: defmt::Formatter) {
        defmt::write!(f, "{}/{=u8}", self.address, self.prefix_len);
    }
}

/// IPv6数据包缓冲区的读写包装器
/// 
/// 提供对IPv6数据包的解析、构建和修改功能
/// IPv6是下一代互联网协议，具有更大的地址空间和改进的功能
#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Packet<T: AsRef<[u8]>> {
    buffer: T,
}

/// IPv6数据包头字段定义
///
/// IPv6数据包头的结构和字段偏移量定义
///
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |Version| Traffic Class |           Flow Label                  |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |         Payload Length        |  Next Header  |   Hop Limit   |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// +                                                               +
/// |                                                               |
/// +                         Source Address                        +
/// |                                                               |
/// +                                                               +
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// +                                                               +
/// |                                                               |
/// +                      Destination Address                      +
/// |                                                               |
/// +                                                               +
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///
/// 详见 https://tools.ietf.org/html/rfc2460#section-3
mod field {
    use crate::wire::field::*;
    // 4位版本号，8位流量类别，和20位流标签
    pub const VER_TC_FLOW: Field = 0..4;
    // 16位有效负载长度值
    // 注意：选项包含在此长度中
    pub const LENGTH: Field = 4..6;
    // 8位值，标识紧随此头部的下一个头部类型
    // 注意：IPv4中使用相同的数字
    pub const NXT_HDR: usize = 6;
    // 8位值，每个转发此数据包的节点都会递减
    // 当值为0时，数据包被丢弃
    pub const HOP_LIMIT: usize = 7;
    // 源节点IPv6地址
    pub const SRC_ADDR: Field = 8..24;
    // 目标节点IPv6地址
    pub const DST_ADDR: Field = 24..40;
}

/// IPv6数据包头的长度（40字节）
pub const HEADER_LEN: usize = field::DST_ADDR.end;

impl<T: AsRef<[u8]>> Packet<T> {
    /// 创建具有IPv6数据包结构的原始字节缓冲区
    ///
    /// 不检查缓冲区长度和有效性，直接创建数据包实例
    #[inline]
    pub const fn new_unchecked(buffer: T) -> Packet<T> {
        Packet { buffer }
    }

    /// [new_unchecked]和[check_len]的组合简写
    ///
    /// 先创建数据包实例，然后检查长度有效性
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    #[inline]
    pub fn new_checked(buffer: T) -> Result<Packet<T>> {
        let packet = Self::new_unchecked(buffer);
        packet.check_len()?;
        Ok(packet)
    }

    /// 确保调用访问器方法时不会panic
    /// 如果缓冲区太短，返回`Err(Error)`
    ///
    /// 调用[set_payload_len]会使此检查结果失效
    ///
    /// [set_payload_len]: #method.set_payload_len
    #[inline]
    pub fn check_len(&self) -> Result<()> {
        let len = self.buffer.as_ref().len();
        if len < field::DST_ADDR.end || len < self.total_len() {
            Err(Error)
        } else {
            Ok(())
        }
    }

    /// 消费数据包，返回底层缓冲区
    #[inline]
    pub fn into_inner(self) -> T {
        self.buffer
    }

    /// 返回数据包头长度（40字节）
    #[inline]
    pub const fn header_len(&self) -> usize {
        // 这不是严格必要的函数，但它使代码更易读
        field::DST_ADDR.end
    }

    /// 返回版本字段（总是6）
    #[inline]
    pub fn version(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::VER_TC_FLOW.start] >> 4
    }

    /// 返回流量类别字段
    #[inline]
    pub fn traffic_class(&self) -> u8 {
        let data = self.buffer.as_ref();
        ((NetworkEndian::read_u16(&data[0..2]) & 0x0ff0) >> 4) as u8
    }

    /// 返回流标签字段
    #[inline]
    pub fn flow_label(&self) -> u32 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u24(&data[1..4]) & 0x000fffff
    }

    /// 返回有效负载长度字段
    #[inline]
    pub fn payload_len(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::LENGTH])
    }

    /// 返回有效负载长度加上已知头部长度的总长度
    #[inline]
    pub fn total_len(&self) -> usize {
        self.header_len() + self.payload_len() as usize
    }

    /// 返回下一个头部字段
    #[inline]
    pub fn next_header(&self) -> Protocol {
        let data = self.buffer.as_ref();
        Protocol::from(data[field::NXT_HDR])
    }

    /// 返回跳数限制字段
    #[inline]
    pub fn hop_limit(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::HOP_LIMIT]
    }

    /// 返回源地址字段
    #[inline]
    pub fn src_addr(&self) -> Address {
        let data = self.buffer.as_ref();
        Address::from_bytes(&data[field::SRC_ADDR])
    }

    /// 返回目的地址字段
    #[inline]
    pub fn dst_addr(&self) -> Address {
        let data = self.buffer.as_ref();
        Address::from_bytes(&data[field::DST_ADDR])
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Packet<&'a T> {
    /// 返回指向有效负载的指针
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        let data = self.buffer.as_ref();
        let range = self.header_len()..self.total_len();
        &data[range]
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    /// 设置版本字段
    #[inline]
    pub fn set_version(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        // 确保保留低位比特，这些比特包含流量类别的高位
        data[0] = (data[0] & 0x0f) | ((value & 0x0f) << 4);
    }

    /// 设置流量类别字段
    #[inline]
    pub fn set_traffic_class(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        // 将值的高4位放入第一个字节的低4位
        data[0] = (data[0] & 0xf0) | ((value & 0xf0) >> 4);
        // 将值的低4位放入第二个字节的高4位
        data[1] = (data[1] & 0x0f) | ((value & 0x0f) << 4);
    }

    /// 设置流标签字段
    #[inline]
    pub fn set_flow_label(&mut self, value: u32) {
        let data = self.buffer.as_mut();
        // 保留流量类别的低4位
        let raw = (((data[1] & 0xf0) as u32) << 16) | (value & 0x0fffff);
        NetworkEndian::write_u24(&mut data[1..4], raw);
    }

    /// 设置有效负载长度字段
    #[inline]
    pub fn set_payload_len(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::LENGTH], value);
    }

    /// 设置下一个头部字段
    #[inline]
    pub fn set_next_header(&mut self, value: Protocol) {
        let data = self.buffer.as_mut();
        data[field::NXT_HDR] = value.into();
    }

    /// 设置跳数限制字段
    #[inline]
    pub fn set_hop_limit(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[field::HOP_LIMIT] = value;
    }

    /// 设置源地址字段
    #[inline]
    pub fn set_src_addr(&mut self, value: Address) {
        let data = self.buffer.as_mut();
        data[field::SRC_ADDR].copy_from_slice(&value.octets());
    }

    /// 设置目的地址字段
    #[inline]
    pub fn set_dst_addr(&mut self, value: Address) {
        let data = self.buffer.as_mut();
        data[field::DST_ADDR].copy_from_slice(&value.octets());
    }

    /// 返回指向有效负载的可变指针
    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let range = self.header_len()..self.total_len();
        let data = self.buffer.as_mut();
        &mut data[range]
    }
}

impl<T: AsRef<[u8]> + ?Sized> fmt::Display for Packet<&T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match Repr::parse(self) {
            Ok(repr) => write!(f, "{repr}"),
            Err(err) => {
                write!(f, "IPv6 ({err})")?;
                Ok(())
            }
        }
    }
}

impl<T: AsRef<[u8]>> AsRef<[u8]> for Packet<T> {
    fn as_ref(&self) -> &[u8] {
        self.buffer.as_ref()
    }
}

/// IPv6数据包头的高级表示
///
/// 提供对IPv6数据包头的抽象表示，包含解析和构造IPv6数据包的功能
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Repr {
    /// 源节点的IPv6地址
    pub src_addr: Address,
    /// 目的节点的IPv6地址
    pub dst_addr: Address,
    /// 下一个头部中包含的协议
    pub next_header: Protocol,
    /// 包括扩展头部在内的有效负载长度
    pub payload_len: usize,
    /// 8位跳数限制字段
    pub hop_limit: u8,
}

impl Repr {
    /// 解析IPv6数据包并返回高级表示
    ///
    /// 从原始数据包中提取关键字段，创建Repr实例用于进一步处理
    pub fn parse<T: AsRef<[u8]> + ?Sized>(packet: &Packet<&T>) -> Result<Repr> {
        // 确保基本访问器可以正常工作
        packet.check_len()?;
        if packet.version() != 6 {
            return Err(Error);
        }
        Ok(Repr {
            src_addr: packet.src_addr(),
            dst_addr: packet.dst_addr(),
            next_header: packet.next_header(),
            payload_len: packet.payload_len() as usize,
            hop_limit: packet.hop_limit(),
        })
    }

    /// 返回从此高级表示发出的数据包头长度
    ///
    /// 计算Repr转换为数据包时所需的缓冲区长度（40字节）
    pub const fn buffer_len(&self) -> usize {
        // 这个函数不是严格必要的，但它可以使客户端代码更易读
        field::DST_ADDR.end
    }

    /// 将高级表示发射到IPv6数据包中
    ///
    /// 根据Repr实例设置数据包的所有字段，包括版本、地址、协议等
    pub fn emit<T: AsRef<[u8]> + AsMut<[u8]>>(&self, packet: &mut Packet<T>) {
        // 不对数据包缓冲区的原始状态做任何假设
        // 确保设置每个字节
        packet.set_version(6);
        packet.set_traffic_class(0);
        packet.set_flow_label(0);
        packet.set_payload_len(self.payload_len as u16);
        packet.set_hop_limit(self.hop_limit);
        packet.set_next_header(self.next_header);
        packet.set_src_addr(self.src_addr);
        packet.set_dst_addr(self.dst_addr);
    }
}

impl fmt::Display for Repr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "IPv6 src={} dst={} nxt_hdr={} hop_limit={}",
            self.src_addr, self.dst_addr, self.next_header, self.hop_limit
        )
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for Repr {
    fn format(&self, fmt: defmt::Formatter) {
        defmt::write!(
            fmt,
            "IPv6 src={} dst={} nxt_hdr={} hop_limit={}",
            self.src_addr,
            self.dst_addr,
            self.next_header,
            self.hop_limit
        )
    }
}

use crate::wire::pretty_print::{PrettyIndent, PrettyPrint};

// TODO: This is very similar to the implementation for IPv4. Make
// a way to have less copy and pasted code here.
impl<T: AsRef<[u8]>> PrettyPrint for Packet<T> {
    fn pretty_print(
        buffer: &dyn AsRef<[u8]>,
        f: &mut fmt::Formatter,
        indent: &mut PrettyIndent,
    ) -> fmt::Result {
        let (ip_repr, payload) = match Packet::new_checked(buffer) {
            Err(err) => return write!(f, "{indent}({err})"),
            Ok(ip_packet) => match Repr::parse(&ip_packet) {
                Err(_) => return Ok(()),
                Ok(ip_repr) => {
                    write!(f, "{indent}{ip_repr}")?;
                    (ip_repr, ip_packet.payload())
                }
            },
        };

        pretty_print_ip_payload(f, indent, ip_repr, payload)
    }
}

#[cfg(test)]
pub(crate) mod test {
    use super::*;
    use crate::wire::pretty_print::PrettyPrinter;

    #[allow(unused)]
    pub(crate) const MOCK_IP_ADDR_1: Address = Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
    #[allow(unused)]
    pub(crate) const MOCK_IP_ADDR_2: Address = Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 2);
    #[allow(unused)]
    pub(crate) const MOCK_IP_ADDR_3: Address = Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 3);
    #[allow(unused)]
    pub(crate) const MOCK_IP_ADDR_4: Address = Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 4);
    #[allow(unused)]
    pub(crate) const MOCK_UNSPECIFIED: Address = Address::UNSPECIFIED;

    const LINK_LOCAL_ADDR: Address = Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
    const UNIQUE_LOCAL_ADDR: Address = Address::new(0xfd00, 0, 0, 201, 1, 1, 1, 1);
    const GLOBAL_UNICAST_ADDR: Address = Address::new(0x2001, 0xdb8, 0x3, 0, 0, 0, 0, 1);

    const TEST_SOL_NODE_MCAST_ADDR: Address = Address::new(0xff02, 0, 0, 0, 0, 1, 0xff01, 101);

    #[test]
    fn test_basic_multicast() {
        assert!(!LINK_LOCAL_ALL_ROUTERS.is_unspecified());
        assert!(LINK_LOCAL_ALL_ROUTERS.is_multicast());
        assert!(!LINK_LOCAL_ALL_ROUTERS.is_link_local());
        assert!(!LINK_LOCAL_ALL_ROUTERS.is_loopback());
        assert!(!LINK_LOCAL_ALL_ROUTERS.x_is_unique_local());
        assert!(!LINK_LOCAL_ALL_ROUTERS.is_global_unicast());
        assert!(!LINK_LOCAL_ALL_ROUTERS.is_solicited_node_multicast());
        assert!(!LINK_LOCAL_ALL_NODES.is_unspecified());
        assert!(LINK_LOCAL_ALL_NODES.is_multicast());
        assert!(!LINK_LOCAL_ALL_NODES.is_link_local());
        assert!(!LINK_LOCAL_ALL_NODES.is_loopback());
        assert!(!LINK_LOCAL_ALL_NODES.x_is_unique_local());
        assert!(!LINK_LOCAL_ALL_NODES.is_global_unicast());
        assert!(!LINK_LOCAL_ALL_NODES.is_solicited_node_multicast());
    }

    #[test]
    fn test_basic_link_local() {
        assert!(!LINK_LOCAL_ADDR.is_unspecified());
        assert!(!LINK_LOCAL_ADDR.is_multicast());
        assert!(LINK_LOCAL_ADDR.is_link_local());
        assert!(!LINK_LOCAL_ADDR.is_loopback());
        assert!(!LINK_LOCAL_ADDR.x_is_unique_local());
        assert!(!LINK_LOCAL_ADDR.is_global_unicast());
        assert!(!LINK_LOCAL_ADDR.is_solicited_node_multicast());
    }

    #[test]
    fn test_basic_loopback() {
        assert!(!Address::LOCALHOST.is_unspecified());
        assert!(!Address::LOCALHOST.is_multicast());
        assert!(!Address::LOCALHOST.is_link_local());
        assert!(Address::LOCALHOST.is_loopback());
        assert!(!Address::LOCALHOST.x_is_unique_local());
        assert!(!Address::LOCALHOST.is_global_unicast());
        assert!(!Address::LOCALHOST.is_solicited_node_multicast());
    }

    #[test]
    fn test_unique_local() {
        assert!(!UNIQUE_LOCAL_ADDR.is_unspecified());
        assert!(!UNIQUE_LOCAL_ADDR.is_multicast());
        assert!(!UNIQUE_LOCAL_ADDR.is_link_local());
        assert!(!UNIQUE_LOCAL_ADDR.is_loopback());
        assert!(UNIQUE_LOCAL_ADDR.x_is_unique_local());
        assert!(!UNIQUE_LOCAL_ADDR.is_global_unicast());
        assert!(!UNIQUE_LOCAL_ADDR.is_solicited_node_multicast());
    }

    #[test]
    fn test_global_unicast() {
        assert!(!GLOBAL_UNICAST_ADDR.is_unspecified());
        assert!(!GLOBAL_UNICAST_ADDR.is_multicast());
        assert!(!GLOBAL_UNICAST_ADDR.is_link_local());
        assert!(!GLOBAL_UNICAST_ADDR.is_loopback());
        assert!(!GLOBAL_UNICAST_ADDR.x_is_unique_local());
        assert!(GLOBAL_UNICAST_ADDR.is_global_unicast());
        assert!(!GLOBAL_UNICAST_ADDR.is_solicited_node_multicast());
    }

    #[test]
    fn test_sollicited_node_multicast() {
        assert!(!TEST_SOL_NODE_MCAST_ADDR.is_unspecified());
        assert!(TEST_SOL_NODE_MCAST_ADDR.is_multicast());
        assert!(!TEST_SOL_NODE_MCAST_ADDR.is_link_local());
        assert!(!TEST_SOL_NODE_MCAST_ADDR.is_loopback());
        assert!(!TEST_SOL_NODE_MCAST_ADDR.x_is_unique_local());
        assert!(!TEST_SOL_NODE_MCAST_ADDR.is_global_unicast());
        assert!(TEST_SOL_NODE_MCAST_ADDR.is_solicited_node_multicast());
    }

    #[test]
    fn test_mask() {
        let addr = Address::new(0x0123, 0x4567, 0x89ab, 0, 0, 0, 0, 1);
        assert_eq!(
            addr.mask(11),
            [0x01, 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            addr.mask(15),
            [0x01, 0x22, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            addr.mask(26),
            [0x01, 0x23, 0x45, 0x40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            addr.mask(128),
            [
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
            ]
        );
        assert_eq!(
            addr.mask(127),
            [
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            ]
        );
    }

    #[test]
    fn test_cidr() {
        // fe80::1/56
        // 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
        // 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        let cidr = Cidr::new(LINK_LOCAL_ADDR, 56);

        let inside_subnet = [
            // fe80::2
            [
                0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x02,
            ],
            // fe80::1122:3344:5566:7788
            [
                0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
                0x77, 0x88,
            ],
            // fe80::ff00:0:0:0
            [
                0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00,
            ],
            // fe80::ff
            [
                0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0xff,
            ],
        ];

        let outside_subnet = [
            // fe80:0:0:101::1
            [
                0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x01,
            ],
            // ::1
            [
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x01,
            ],
            // ff02::1
            [
                0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x01,
            ],
            // ff02::2
            [
                0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x02,
            ],
        ];

        let subnets = [
            // fe80::ffff:ffff:ffff:ffff/65
            (
                [
                    0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff,
                ],
                65,
            ),
            // fe80::1/128
            (
                [
                    0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x01,
                ],
                128,
            ),
            // fe80::1234:5678/96
            (
                [
                    0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12,
                    0x34, 0x56, 0x78,
                ],
                96,
            ),
        ];

        let not_subnets = [
            // fe80::101:ffff:ffff:ffff:ffff/55
            (
                [
                    0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff,
                ],
                55,
            ),
            // fe80::101:ffff:ffff:ffff:ffff/56
            (
                [
                    0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff,
                ],
                56,
            ),
            // fe80::101:ffff:ffff:ffff:ffff/57
            (
                [
                    0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff,
                ],
                57,
            ),
            // ::1/128
            (
                [
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x01,
                ],
                128,
            ),
        ];

        for addr in inside_subnet.iter().map(|a| Address::from_bytes(a)) {
            assert!(cidr.contains_addr(&addr));
        }

        for addr in outside_subnet.iter().map(|a| Address::from_bytes(a)) {
            assert!(!cidr.contains_addr(&addr));
        }

        for subnet in subnets.iter().map(|&(a, p)| Cidr::new(Address::from(a), p)) {
            assert!(cidr.contains_subnet(&subnet));
        }

        for subnet in not_subnets
            .iter()
            .map(|&(a, p)| Cidr::new(Address::from(a), p))
        {
            assert!(!cidr.contains_subnet(&subnet));
        }

        let cidr_without_prefix = Cidr::new(LINK_LOCAL_ADDR, 0);
        assert!(cidr_without_prefix.contains_addr(&Address::LOCALHOST));
    }

    #[test]
    #[should_panic(expected = "length")]
    fn test_from_bytes_too_long() {
        let _ = Address::from_bytes(&[0u8; 15]);
    }

    #[test]
    fn test_scope() {
        use super::*;
        assert_eq!(
            Address::new(0xff01, 0, 0, 0, 0, 0, 0, 1).x_multicast_scope(),
            MulticastScope::InterfaceLocal
        );
        assert_eq!(
            Address::new(0xff02, 0, 0, 0, 0, 0, 0, 1).x_multicast_scope(),
            MulticastScope::LinkLocal
        );
        assert_eq!(
            Address::new(0xff03, 0, 0, 0, 0, 0, 0, 1).x_multicast_scope(),
            MulticastScope::Unknown
        );
        assert_eq!(
            Address::new(0xff04, 0, 0, 0, 0, 0, 0, 1).x_multicast_scope(),
            MulticastScope::AdminLocal
        );
        assert_eq!(
            Address::new(0xff05, 0, 0, 0, 0, 0, 0, 1).x_multicast_scope(),
            MulticastScope::SiteLocal
        );
        assert_eq!(
            Address::new(0xff08, 0, 0, 0, 0, 0, 0, 1).x_multicast_scope(),
            MulticastScope::OrganizationLocal
        );
        assert_eq!(
            Address::new(0xff0e, 0, 0, 0, 0, 0, 0, 1).x_multicast_scope(),
            MulticastScope::Global
        );

        assert_eq!(
            LINK_LOCAL_ALL_NODES.x_multicast_scope(),
            MulticastScope::LinkLocal
        );

        // For source address selection, unicast addresses also have a scope:
        assert_eq!(
            LINK_LOCAL_ADDR.x_multicast_scope(),
            MulticastScope::LinkLocal
        );
        assert_eq!(
            GLOBAL_UNICAST_ADDR.x_multicast_scope(),
            MulticastScope::Global
        );
        assert_eq!(
            UNIQUE_LOCAL_ADDR.x_multicast_scope(),
            MulticastScope::Global
        );
    }

    static REPR_PACKET_BYTES: [u8; 52] = [
        0x60, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x11, 0x40, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0x00,
        0x0c, 0x02, 0x4e, 0xff, 0xff, 0xff, 0xff,
    ];
    static REPR_PAYLOAD_BYTES: [u8; 12] = [
        0x00, 0x01, 0x00, 0x02, 0x00, 0x0c, 0x02, 0x4e, 0xff, 0xff, 0xff, 0xff,
    ];

    const fn packet_repr() -> Repr {
        Repr {
            src_addr: Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
            dst_addr: LINK_LOCAL_ALL_NODES,
            next_header: Protocol::Udp,
            payload_len: 12,
            hop_limit: 64,
        }
    }

    #[test]
    fn test_packet_deconstruction() {
        let packet = Packet::new_unchecked(&REPR_PACKET_BYTES[..]);
        assert_eq!(packet.check_len(), Ok(()));
        assert_eq!(packet.version(), 6);
        assert_eq!(packet.traffic_class(), 0);
        assert_eq!(packet.flow_label(), 0);
        assert_eq!(packet.total_len(), 0x34);
        assert_eq!(packet.payload_len() as usize, REPR_PAYLOAD_BYTES.len());
        assert_eq!(packet.next_header(), Protocol::Udp);
        assert_eq!(packet.hop_limit(), 0x40);
        assert_eq!(packet.src_addr(), Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
        assert_eq!(packet.dst_addr(), LINK_LOCAL_ALL_NODES);
        assert_eq!(packet.payload(), &REPR_PAYLOAD_BYTES[..]);
    }

    #[test]
    fn test_packet_construction() {
        let mut bytes = [0xff; 52];
        let mut packet = Packet::new_unchecked(&mut bytes[..]);
        // Version, Traffic Class, and Flow Label are not
        // byte aligned. make sure the setters and getters
        // do not interfere with each other.
        packet.set_version(6);
        assert_eq!(packet.version(), 6);
        packet.set_traffic_class(0x99);
        assert_eq!(packet.version(), 6);
        assert_eq!(packet.traffic_class(), 0x99);
        packet.set_flow_label(0x54321);
        assert_eq!(packet.traffic_class(), 0x99);
        assert_eq!(packet.flow_label(), 0x54321);
        packet.set_payload_len(0xc);
        packet.set_next_header(Protocol::Udp);
        packet.set_hop_limit(0xfe);
        packet.set_src_addr(LINK_LOCAL_ALL_ROUTERS);
        packet.set_dst_addr(LINK_LOCAL_ALL_NODES);
        packet
            .payload_mut()
            .copy_from_slice(&REPR_PAYLOAD_BYTES[..]);
        let mut expected_bytes = [
            0x69, 0x95, 0x43, 0x21, 0x00, 0x0c, 0x11, 0xfe, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x02, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let start = expected_bytes.len() - REPR_PAYLOAD_BYTES.len();
        expected_bytes[start..].copy_from_slice(&REPR_PAYLOAD_BYTES[..]);
        assert_eq!(packet.check_len(), Ok(()));
        assert_eq!(&*packet.into_inner(), &expected_bytes[..]);
    }

    #[test]
    fn test_overlong() {
        let mut bytes = vec![];
        bytes.extend(&REPR_PACKET_BYTES[..]);
        bytes.push(0);

        assert_eq!(
            Packet::new_unchecked(&bytes).payload().len(),
            REPR_PAYLOAD_BYTES.len()
        );
        assert_eq!(
            Packet::new_unchecked(&mut bytes).payload_mut().len(),
            REPR_PAYLOAD_BYTES.len()
        );
    }

    #[test]
    fn test_total_len_overflow() {
        let mut bytes = vec![];
        bytes.extend(&REPR_PACKET_BYTES[..]);
        Packet::new_unchecked(&mut bytes).set_payload_len(0x80);

        assert_eq!(Packet::new_checked(&bytes).unwrap_err(), Error);
    }

    #[test]
    fn test_repr_parse_valid() {
        let packet = Packet::new_unchecked(&REPR_PACKET_BYTES[..]);
        let repr = Repr::parse(&packet).unwrap();
        assert_eq!(repr, packet_repr());
    }

    #[test]
    fn test_repr_parse_bad_version() {
        let mut bytes = [0; 40];
        let mut packet = Packet::new_unchecked(&mut bytes[..]);
        packet.set_version(4);
        packet.set_payload_len(0);
        let packet = Packet::new_unchecked(&*packet.into_inner());
        assert_eq!(Repr::parse(&packet), Err(Error));
    }

    #[test]
    fn test_repr_parse_smaller_than_header() {
        let mut bytes = [0; 40];
        let mut packet = Packet::new_unchecked(&mut bytes[..]);
        packet.set_version(6);
        packet.set_payload_len(39);
        let packet = Packet::new_unchecked(&*packet.into_inner());
        assert_eq!(Repr::parse(&packet), Err(Error));
    }

    #[test]
    fn test_repr_parse_smaller_than_payload() {
        let mut bytes = [0; 40];
        let mut packet = Packet::new_unchecked(&mut bytes[..]);
        packet.set_version(6);
        packet.set_payload_len(1);
        let packet = Packet::new_unchecked(&*packet.into_inner());
        assert_eq!(Repr::parse(&packet), Err(Error));
    }

    #[test]
    fn test_basic_repr_emit() {
        let repr = packet_repr();
        let mut bytes = vec![0xff; repr.buffer_len() + REPR_PAYLOAD_BYTES.len()];
        let mut packet = Packet::new_unchecked(&mut bytes);
        repr.emit(&mut packet);
        packet.payload_mut().copy_from_slice(&REPR_PAYLOAD_BYTES);
        assert_eq!(&*packet.into_inner(), &REPR_PACKET_BYTES[..]);
    }

    #[test]
    fn test_pretty_print() {
        assert_eq!(
            format!(
                "{}",
                PrettyPrinter::<Packet<&'static [u8]>>::new("\n", &&REPR_PACKET_BYTES[..])
            ),
            "\nIPv6 src=fe80::1 dst=ff02::1 nxt_hdr=UDP hop_limit=64\n \\ UDP src=1 dst=2 len=4"
        );
    }
}
