use core::cmp::min;
#[cfg(feature = "async")]
use core::task::Waker;

use crate::iface::Context;
use crate::socket::PollAt;
#[cfg(feature = "async")]
use crate::socket::WakerRegistration;

use crate::storage::Empty;
use crate::wire::{IpProtocol, IpRepr, IpVersion};
#[cfg(feature = "proto-ipv4")]
use crate::wire::{Ipv4Packet, Ipv4Repr};
#[cfg(feature = "proto-ipv6")]
use crate::wire::{Ipv6Packet, Ipv6Repr};

/// 原始套接字绑定操作返回的错误类型
/// 
/// 当原始套接字绑定操作失败时返回此错误
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum BindError {
    InvalidState,
    Unaddressable,
}

impl core::fmt::Display for BindError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            BindError::InvalidState => write!(f, "invalid state"),
            BindError::Unaddressable => write!(f, "unaddressable"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for BindError {}

/// 原始套接字发送操作返回的错误类型
/// 
/// 当原始套接字发送操作失败时返回此错误
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum SendError {
    BufferFull,
}

impl core::fmt::Display for SendError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            SendError::BufferFull => write!(f, "buffer full"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SendError {}

/// 原始套接字接收操作返回的错误类型
/// 
/// 当原始套接字接收操作失败时返回此错误
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum RecvError {
    Exhausted,
    Truncated,
}

impl core::fmt::Display for RecvError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            RecvError::Exhausted => write!(f, "exhausted"),
            RecvError::Truncated => write!(f, "truncated"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for RecvError {}

/// UDP数据包元数据类型
/// 
/// 用于存储原始套接字数据包的元信息
pub type PacketMetadata = crate::storage::PacketMetadata<()>;

/// UDP数据包环形缓冲区类型
/// 
/// 用于存储原始套接字数据包的环形缓冲区
pub type PacketBuffer<'a> = crate::storage::PacketBuffer<'a, ()>;

/// 原始IP套接字
///
/// 原始套接字可以绑定到特定的IP版本和数据报协议，并拥有发送和接收数据包缓冲区
/// 
/// 原始套接字允许直接访问IP层数据包，用于实现自定义协议或网络工具
#[derive(Debug)]
pub struct Socket<'a> {
    ip_version: Option<IpVersion>,
    ip_protocol: Option<IpProtocol>,
    rx_buffer: PacketBuffer<'a>,
    tx_buffer: PacketBuffer<'a>,
    #[cfg(feature = "async")]
    rx_waker: WakerRegistration,
    #[cfg(feature = "async")]
    tx_waker: WakerRegistration,
}

impl<'a> Socket<'a> {
    /// 创建绑定到指定IP版本和数据报协议的原始IP套接字，使用给定的缓冲区
    /// 
    /// 创建一个新的原始套接字实例，可以指定IP版本和协议类型
    pub fn new(
        ip_version: Option<IpVersion>,
        ip_protocol: Option<IpProtocol>,
        rx_buffer: PacketBuffer<'a>,
        tx_buffer: PacketBuffer<'a>,
    ) -> Socket<'a> {
        Socket {
            ip_version,
            ip_protocol,
            rx_buffer,
            tx_buffer,
            #[cfg(feature = "async")]
            rx_waker: WakerRegistration::new(),
            #[cfg(feature = "async")]
            tx_waker: WakerRegistration::new(),
        }
    }

    /// 注册接收操作的唤醒器
    ///
    /// 当可能影响`recv`方法返回值的状态变化时唤醒，如接收到数据或套接字关闭
    ///
    /// 注意事项：
    ///
    /// - 一次只能注册一个唤醒器。如果之前注册了另一个唤醒器，它将被覆盖且不再被唤醒
    /// - 唤醒器只唤醒一次。一旦唤醒，必须重新注册才能接收更多唤醒
    /// - 允许"虚假唤醒"：唤醒不保证`recv`的结果必然发生变化
    #[cfg(feature = "async")]
    pub fn register_recv_waker(&mut self, waker: &Waker) {
        self.rx_waker.register(waker)
    }

    /// 注册发送操作的唤醒器
    ///
    /// 当可能影响`send`方法返回值的状态变化时唤醒，如发送缓冲区有空间可用或套接字关闭
    ///
    /// 注意事项：
    ///
    /// - 一次只能注册一个唤醒器。如果之前注册了另一个唤醒器，它将被覆盖且不再被唤醒
    /// - 唤醒器只唤醒一次。一旦唤醒，必须重新注册才能接收更多唤醒
    /// - 允许"虚假唤醒"：唤醒不保证`send`的结果必然发生变化
    #[cfg(feature = "async")]
    pub fn register_send_waker(&mut self, waker: &Waker) {
        self.tx_waker.register(waker)
    }

    /// 返回套接字绑定的IP版本
    /// 
    /// 获取此原始套接字绑定的IP协议版本（IPv4或IPv6）
    #[inline]
    pub fn ip_version(&self) -> Option<IpVersion> {
        self.ip_version
    }

    /// 返回套接字绑定的IP协议
    /// 
    /// 获取此原始套接字绑定的IP协议类型（如TCP、UDP或其他自定义协议）
    #[inline]
    pub fn ip_protocol(&self) -> Option<IpProtocol> {
        self.ip_protocol
    }

    /// 检查发送缓冲区是否已满
    /// 
    /// 返回true表示发送缓冲区还有空间，可以继续发送数据
    #[inline]
    pub fn can_send(&self) -> bool {
        !self.tx_buffer.is_full()
    }

    /// 检查接收缓冲区是否不为空
    /// 
    /// 返回true表示接收缓冲区中有数据可以读取
    #[inline]
    pub fn can_recv(&self) -> bool {
        !self.rx_buffer.is_empty()
    }

    /// 返回套接字可以接收的最大数据包数量
    /// 
    /// 获取接收缓冲区的数据包容量上限
    #[inline]
    pub fn packet_recv_capacity(&self) -> usize {
        self.rx_buffer.packet_capacity()
    }

    /// 返回套接字可以发送的最大数据包数量
    /// 
    /// 获取发送缓冲区的数据包容量上限
    #[inline]
    pub fn packet_send_capacity(&self) -> usize {
        self.tx_buffer.packet_capacity()
    }

    /// 返回接收缓冲区中的最大字节数
    /// 
    /// 获取接收缓冲区的负载数据容量上限（以字节为单位）
    #[inline]
    pub fn payload_recv_capacity(&self) -> usize {
        self.rx_buffer.payload_capacity()
    }

    /// 返回发送缓冲区中的最大字节数
    /// 
    /// 获取发送缓冲区的负载数据容量上限（以字节为单位）
    #[inline]
    pub fn payload_send_capacity(&self) -> usize {
        self.tx_buffer.payload_capacity()
    }

    /// 将数据包加入发送队列，并返回指向其负载的指针
    ///
    /// 如果发送缓冲区已满，此函数返回`Err(SendError::BufferFull)`
    /// 如果没有足够的发送缓冲区容量来发送此数据包，返回`Err(SendError::Truncated)`
    ///
    /// 如果填充缓冲区的方式与套接字的IP版本或协议不匹配，数据包将被静默丢弃
    ///
    /// **注意：** IP头部会被解析并重新序列化，可能与实际传输的头部不完全一致
    pub fn send(&mut self, size: usize) -> Result<&mut [u8], SendError> {
        let packet_buf = self
            .tx_buffer
            .enqueue(size, ())
            .map_err(|_| SendError::BufferFull)?;

        net_trace!(
            "raw:{:?}:{:?}: buffer to send {} octets",
            self.ip_version,
            self.ip_protocol,
            packet_buf.len()
        );
        Ok(packet_buf)
    }

    /// 将数据包加入发送队列，并将缓冲区传递给提供的闭包
    /// 闭包返回写入缓冲区的数据大小
    ///
    /// 另见 [send](#method.send) 方法
    pub fn send_with<F>(&mut self, max_size: usize, f: F) -> Result<usize, SendError>
    where
        F: FnOnce(&mut [u8]) -> usize,
    {
        let size = self
            .tx_buffer
            .enqueue_with_infallible(max_size, (), f)
            .map_err(|_| SendError::BufferFull)?;

        net_trace!(
            "raw:{:?}:{:?}: buffer to send {} octets",
            self.ip_version,
            self.ip_protocol,
            size
        );

        Ok(size)
    }

    /// 将数据包加入发送队列，并从切片填充数据
    ///
    /// 另见 [send](#method.send) 方法
    pub fn send_slice(&mut self, data: &[u8]) -> Result<(), SendError> {
        self.send(data.len())?.copy_from_slice(data);
        Ok(())
    }

    /// 从队列中取出数据包，并返回指向负载的指针
    ///
    /// 如果接收缓冲区为空，此函数返回`Err(RecvError::Exhausted)`
    ///
    /// **注意：** IP头部会被解析并重新序列化，可能与实际接收的头部不完全一致
    pub fn recv(&mut self) -> Result<&[u8], RecvError> {
        let ((), packet_buf) = self.rx_buffer.dequeue().map_err(|_| RecvError::Exhausted)?;

        net_trace!(
            "raw:{:?}:{:?}: receive {} buffered octets",
            self.ip_version,
            self.ip_protocol,
            packet_buf.len()
        );
        Ok(packet_buf)
    }

    /// 从队列中取出数据包，并将负载复制到给定的切片中
    ///
    /// **注意**：当提供的缓冲区大小小于负载大小时，数据包将被丢弃并返回`RecvError::Truncated`错误
    ///
    /// 另见 [recv](#method.recv) 方法
    pub fn recv_slice(&mut self, data: &mut [u8]) -> Result<usize, RecvError> {
        let buffer = self.recv()?;
        if data.len() < buffer.len() {
            return Err(RecvError::Truncated);
        }

        let length = min(data.len(), buffer.len());
        data[..length].copy_from_slice(&buffer[..length]);
        Ok(length)
    }

    /// 查看接收缓冲区中的数据包，并返回指向负载的指针，但不从接收缓冲区移除该数据包
    /// 此函数在其他方面与[recv](#method.recv)行为相同
    ///
    /// 如果接收缓冲区为空，返回`Err(RecvError::Exhausted)`
    pub fn peek(&mut self) -> Result<&[u8], RecvError> {
        let ((), packet_buf) = self.rx_buffer.peek().map_err(|_| RecvError::Exhausted)?;

        net_trace!(
            "raw:{:?}:{:?}: receive {} buffered octets",
            self.ip_version,
            self.ip_protocol,
            packet_buf.len()
        );

        Ok(packet_buf)
    }

    /// 查看接收缓冲区中的数据包，将负载复制到给定的切片中，并返回复制的字节数，但不从接收缓冲区移除该数据包
    /// 此函数在其他方面与[recv_slice](#method.recv_slice)行为相同
    ///
    /// **注意**：当提供的缓冲区大小小于负载大小时，不会将数据复制到提供的缓冲区中，并返回`RecvError::Truncated`错误
    ///
    /// 另见 [peek](#method.peek) 方法
    pub fn peek_slice(&mut self, data: &mut [u8]) -> Result<usize, RecvError> {
        let buffer = self.peek()?;
        if data.len() < buffer.len() {
            return Err(RecvError::Truncated);
        }

        let length = min(data.len(), buffer.len());
        data[..length].copy_from_slice(&buffer[..length]);
        Ok(length)
    }

    /// 返回发送缓冲区中排队的字节数
    /// 
    /// 获取当前发送缓冲区中等待发送的数据量
    pub fn send_queue(&self) -> usize {
        self.tx_buffer.payload_bytes_count()
    }

    /// 返回接收缓冲区中排队的字节数
    /// 
    /// 获取当前接收缓冲区中已接收但尚未处理的数据量
    pub fn recv_queue(&self) -> usize {
        self.rx_buffer.payload_bytes_count()
    }

    pub(crate) fn accepts(&self, ip_repr: &IpRepr) -> bool {
        if self
            .ip_version
            .is_some_and(|version| version != ip_repr.version())
        {
            return false;
        }

        if self
            .ip_protocol
            .is_some_and(|next_header| next_header != ip_repr.next_header())
        {
            return false;
        }

        true
    }

    pub(crate) fn process(&mut self, cx: &mut Context, ip_repr: &IpRepr, payload: &[u8]) {
        debug_assert!(self.accepts(ip_repr));

        let header_len = ip_repr.header_len();
        let total_len = header_len + payload.len();

        net_trace!(
            "raw:{:?}:{:?}: receiving {} octets",
            self.ip_version,
            self.ip_protocol,
            total_len
        );

        match self.rx_buffer.enqueue(total_len, ()) {
            Ok(buf) => {
                ip_repr.emit(&mut buf[..header_len], &cx.checksum_caps());
                buf[header_len..].copy_from_slice(payload);
            }
            Err(_) => net_trace!(
                "raw:{:?}:{:?}: buffer full, dropped incoming packet",
                self.ip_version,
                self.ip_protocol
            ),
        }

        #[cfg(feature = "async")]
        self.rx_waker.wake();
    }

    pub(crate) fn dispatch<F, E>(&mut self, cx: &mut Context, emit: F) -> Result<(), E>
    where
        F: FnOnce(&mut Context, (IpRepr, &[u8])) -> Result<(), E>,
    {
        let ip_protocol = self.ip_protocol;
        let ip_version = self.ip_version;
        let _checksum_caps = &cx.checksum_caps();
        let res = self.tx_buffer.dequeue_with(|&mut (), buffer| {
            match IpVersion::of_packet(buffer) {
                #[cfg(feature = "proto-ipv4")]
                Ok(IpVersion::Ipv4) => {
                    let mut packet = match Ipv4Packet::new_checked(buffer) {
                        Ok(x) => x,
                        Err(_) => {
                            net_trace!("raw: malformed ipv6 packet in queue, dropping.");
                            return Ok(());
                        }
                    };
                    if ip_protocol.is_some_and(|next_header| next_header != packet.next_header()) {
                        net_trace!("raw: sent packet with wrong ip protocol, dropping.");
                        return Ok(());
                    }
                    if _checksum_caps.ipv4.tx() {
                        packet.fill_checksum();
                    } else {
                        // make sure we get a consistently zeroed checksum,
                        // since implementations might rely on it
                        packet.set_checksum(0);
                    }

                    let packet = Ipv4Packet::new_unchecked(&*packet.into_inner());
                    let ipv4_repr = match Ipv4Repr::parse(&packet, _checksum_caps) {
                        Ok(x) => x,
                        Err(_) => {
                            net_trace!("raw: malformed ipv4 packet in queue, dropping.");
                            return Ok(());
                        }
                    };
                    net_trace!("raw:{:?}:{:?}: sending", ip_version, ip_protocol);
                    emit(cx, (IpRepr::Ipv4(ipv4_repr), packet.payload()))
                }
                #[cfg(feature = "proto-ipv6")]
                Ok(IpVersion::Ipv6) => {
                    let packet = match Ipv6Packet::new_checked(buffer) {
                        Ok(x) => x,
                        Err(_) => {
                            net_trace!("raw: malformed ipv6 packet in queue, dropping.");
                            return Ok(());
                        }
                    };
                    if ip_protocol.is_some_and(|next_header| next_header != packet.next_header()) {
                        net_trace!("raw: sent ipv6 packet with wrong ip protocol, dropping.");
                        return Ok(());
                    }
                    let packet = Ipv6Packet::new_unchecked(&*packet.into_inner());
                    let ipv6_repr = match Ipv6Repr::parse(&packet) {
                        Ok(x) => x,
                        Err(_) => {
                            net_trace!("raw: malformed ipv6 packet in queue, dropping.");
                            return Ok(());
                        }
                    };

                    net_trace!("raw:{:?}:{:?}: sending", ip_version, ip_protocol);
                    emit(cx, (IpRepr::Ipv6(ipv6_repr), packet.payload()))
                }
                Err(_) => {
                    net_trace!("raw: sent packet with invalid IP version, dropping.");
                    Ok(())
                }
            }
        });
        match res {
            Err(Empty) => Ok(()),
            Ok(Err(e)) => Err(e),
            Ok(Ok(())) => {
                #[cfg(feature = "async")]
                self.tx_waker.wake();
                Ok(())
            }
        }
    }

    pub(crate) fn poll_at(&self, _cx: &mut Context) -> PollAt {
        if self.tx_buffer.is_empty() {
            PollAt::Ingress
        } else {
            PollAt::Now
        }
    }
}

#[cfg(test)]
mod test {
    use crate::phy::Medium;
    use crate::tests::setup;
    use rstest::*;

    use super::*;
    use crate::wire::IpRepr;
    #[cfg(feature = "proto-ipv4")]
    use crate::wire::{Ipv4Address, Ipv4Repr};
    #[cfg(feature = "proto-ipv6")]
    use crate::wire::{Ipv6Address, Ipv6Repr};

    fn buffer(packets: usize) -> PacketBuffer<'static> {
        PacketBuffer::new(vec![PacketMetadata::EMPTY; packets], vec![0; 48 * packets])
    }

    #[cfg(feature = "proto-ipv4")]
    mod ipv4_locals {
        use super::*;

        pub fn socket(
            rx_buffer: PacketBuffer<'static>,
            tx_buffer: PacketBuffer<'static>,
        ) -> Socket<'static> {
            Socket::new(
                Some(IpVersion::Ipv4),
                Some(IpProtocol::Unknown(IP_PROTO)),
                rx_buffer,
                tx_buffer,
            )
        }

        pub const IP_PROTO: u8 = 63;
        pub const HEADER_REPR: IpRepr = IpRepr::Ipv4(Ipv4Repr {
            src_addr: Ipv4Address::new(10, 0, 0, 1),
            dst_addr: Ipv4Address::new(10, 0, 0, 2),
            next_header: IpProtocol::Unknown(IP_PROTO),
            payload_len: 4,
            hop_limit: 64,
        });
        pub const PACKET_BYTES: [u8; 24] = [
            0x45, 0x00, 0x00, 0x18, 0x00, 0x00, 0x40, 0x00, 0x40, 0x3f, 0x00, 0x00, 0x0a, 0x00,
            0x00, 0x01, 0x0a, 0x00, 0x00, 0x02, 0xaa, 0x00, 0x00, 0xff,
        ];
        pub const PACKET_PAYLOAD: [u8; 4] = [0xaa, 0x00, 0x00, 0xff];
    }

    #[cfg(feature = "proto-ipv6")]
    mod ipv6_locals {
        use super::*;

        pub fn socket(
            rx_buffer: PacketBuffer<'static>,
            tx_buffer: PacketBuffer<'static>,
        ) -> Socket<'static> {
            Socket::new(
                Some(IpVersion::Ipv6),
                Some(IpProtocol::Unknown(IP_PROTO)),
                rx_buffer,
                tx_buffer,
            )
        }

        pub const IP_PROTO: u8 = 63;
        pub const HEADER_REPR: IpRepr = IpRepr::Ipv6(Ipv6Repr {
            src_addr: Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
            dst_addr: Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 2),
            next_header: IpProtocol::Unknown(IP_PROTO),
            payload_len: 4,
            hop_limit: 64,
        });

        pub const PACKET_BYTES: [u8; 44] = [
            0x60, 0x00, 0x00, 0x00, 0x00, 0x04, 0x3f, 0x40, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xfe, 0x80, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xaa, 0x00,
            0x00, 0xff,
        ];

        pub const PACKET_PAYLOAD: [u8; 4] = [0xaa, 0x00, 0x00, 0xff];
    }

    macro_rules! reusable_ip_specific_tests {
        ($module:ident, $socket:path, $hdr:path, $packet:path, $payload:path) => {
            mod $module {
                use super::*;

                #[test]
                fn test_send_truncated() {
                    let mut socket = $socket(buffer(0), buffer(1));
                    assert_eq!(socket.send_slice(&[0; 56][..]), Err(SendError::BufferFull));
                }

                #[rstest]
                #[case::ip(Medium::Ip)]
                #[cfg(feature = "medium-ip")]
                #[case::ethernet(Medium::Ethernet)]
                #[cfg(feature = "medium-ethernet")]
                #[case::ieee802154(Medium::Ieee802154)]
                #[cfg(feature = "medium-ieee802154")]
                fn test_send_dispatch(#[case] medium: Medium) {
                    let (mut iface, _, _) = setup(medium);
                    let mut cx = iface.context();
                    let mut socket = $socket(buffer(0), buffer(1));

                    assert!(socket.can_send());
                    assert_eq!(
                        socket.dispatch(&mut cx, |_, _| unreachable!()),
                        Ok::<_, ()>(())
                    );

                    assert_eq!(socket.send_slice(&$packet[..]), Ok(()));
                    assert_eq!(socket.send_slice(b""), Err(SendError::BufferFull));
                    assert!(!socket.can_send());

                    assert_eq!(
                        socket.dispatch(&mut cx, |_, (ip_repr, ip_payload)| {
                            assert_eq!(ip_repr, $hdr);
                            assert_eq!(ip_payload, &$payload);
                            Err(())
                        }),
                        Err(())
                    );
                    assert!(!socket.can_send());

                    assert_eq!(
                        socket.dispatch(&mut cx, |_, (ip_repr, ip_payload)| {
                            assert_eq!(ip_repr, $hdr);
                            assert_eq!(ip_payload, &$payload);
                            Ok::<_, ()>(())
                        }),
                        Ok(())
                    );
                    assert!(socket.can_send());
                }

                #[rstest]
                #[case::ip(Medium::Ip)]
                #[cfg(feature = "medium-ip")]
                #[case::ethernet(Medium::Ethernet)]
                #[cfg(feature = "medium-ethernet")]
                #[case::ieee802154(Medium::Ieee802154)]
                #[cfg(feature = "medium-ieee802154")]
                fn test_recv_truncated_slice(#[case] medium: Medium) {
                    let (mut iface, _, _) = setup(medium);
                    let mut cx = iface.context();
                    let mut socket = $socket(buffer(1), buffer(0));

                    assert!(socket.accepts(&$hdr));
                    socket.process(&mut cx, &$hdr, &$payload);

                    let mut slice = [0; 4];
                    assert_eq!(socket.recv_slice(&mut slice[..]), Err(RecvError::Truncated));
                }

                #[rstest]
                #[case::ip(Medium::Ip)]
                #[cfg(feature = "medium-ip")]
                #[case::ethernet(Medium::Ethernet)]
                #[cfg(feature = "medium-ethernet")]
                #[case::ieee802154(Medium::Ieee802154)]
                #[cfg(feature = "medium-ieee802154")]
                fn test_recv_truncated_packet(#[case] medium: Medium) {
                    let (mut iface, _, _) = setup(medium);
                    let mut cx = iface.context();
                    let mut socket = $socket(buffer(1), buffer(0));

                    let mut buffer = vec![0; 128];
                    buffer[..$packet.len()].copy_from_slice(&$packet[..]);

                    assert!(socket.accepts(&$hdr));
                    socket.process(&mut cx, &$hdr, &buffer);
                }

                #[rstest]
                #[case::ip(Medium::Ip)]
                #[cfg(feature = "medium-ip")]
                #[case::ethernet(Medium::Ethernet)]
                #[cfg(feature = "medium-ethernet")]
                #[case::ieee802154(Medium::Ieee802154)]
                #[cfg(feature = "medium-ieee802154")]
                fn test_peek_truncated_slice(#[case] medium: Medium) {
                    let (mut iface, _, _) = setup(medium);
                    let mut cx = iface.context();
                    let mut socket = $socket(buffer(1), buffer(0));

                    assert!(socket.accepts(&$hdr));
                    socket.process(&mut cx, &$hdr, &$payload);

                    let mut slice = [0; 4];
                    assert_eq!(socket.peek_slice(&mut slice[..]), Err(RecvError::Truncated));
                    assert_eq!(socket.recv_slice(&mut slice[..]), Err(RecvError::Truncated));
                    assert_eq!(socket.peek_slice(&mut slice[..]), Err(RecvError::Exhausted));
                }
            }
        };
    }

    #[cfg(feature = "proto-ipv4")]
    reusable_ip_specific_tests!(
        ipv4,
        ipv4_locals::socket,
        ipv4_locals::HEADER_REPR,
        ipv4_locals::PACKET_BYTES,
        ipv4_locals::PACKET_PAYLOAD
    );

    #[cfg(feature = "proto-ipv6")]
    reusable_ip_specific_tests!(
        ipv6,
        ipv6_locals::socket,
        ipv6_locals::HEADER_REPR,
        ipv6_locals::PACKET_BYTES,
        ipv6_locals::PACKET_PAYLOAD
    );

    #[rstest]
    #[case::ip(Medium::Ip)]
    #[case::ethernet(Medium::Ethernet)]
    #[cfg(feature = "medium-ethernet")]
    #[case::ieee802154(Medium::Ieee802154)]
    #[cfg(feature = "medium-ieee802154")]
    fn test_send_illegal(#[case] medium: Medium) {
        #[cfg(feature = "proto-ipv4")]
        {
            let (mut iface, _, _) = setup(medium);
            let cx = iface.context();
            let mut socket = ipv4_locals::socket(buffer(0), buffer(2));

            let mut wrong_version = ipv4_locals::PACKET_BYTES;
            Ipv4Packet::new_unchecked(&mut wrong_version).set_version(6);

            assert_eq!(socket.send_slice(&wrong_version[..]), Ok(()));
            assert_eq!(socket.dispatch(cx, |_, _| unreachable!()), Ok::<_, ()>(()));

            let mut wrong_protocol = ipv4_locals::PACKET_BYTES;
            Ipv4Packet::new_unchecked(&mut wrong_protocol).set_next_header(IpProtocol::Tcp);

            assert_eq!(socket.send_slice(&wrong_protocol[..]), Ok(()));
            assert_eq!(socket.dispatch(cx, |_, _| unreachable!()), Ok::<_, ()>(()));
        }
        #[cfg(feature = "proto-ipv6")]
        {
            let (mut iface, _, _) = setup(medium);
            let cx = iface.context();
            let mut socket = ipv6_locals::socket(buffer(0), buffer(2));

            let mut wrong_version = ipv6_locals::PACKET_BYTES;
            Ipv6Packet::new_unchecked(&mut wrong_version[..]).set_version(4);

            assert_eq!(socket.send_slice(&wrong_version[..]), Ok(()));
            assert_eq!(socket.dispatch(cx, |_, _| unreachable!()), Ok::<_, ()>(()));

            let mut wrong_protocol = ipv6_locals::PACKET_BYTES;
            Ipv6Packet::new_unchecked(&mut wrong_protocol[..]).set_next_header(IpProtocol::Tcp);

            assert_eq!(socket.send_slice(&wrong_protocol[..]), Ok(()));
            assert_eq!(socket.dispatch(cx, |_, _| unreachable!()), Ok::<_, ()>(()));
        }
    }

    #[rstest]
    #[case::ip(Medium::Ip)]
    #[cfg(feature = "medium-ip")]
    #[case::ethernet(Medium::Ethernet)]
    #[cfg(feature = "medium-ethernet")]
    #[case::ieee802154(Medium::Ieee802154)]
    #[cfg(feature = "medium-ieee802154")]
    fn test_recv_process(#[case] medium: Medium) {
        #[cfg(feature = "proto-ipv4")]
        {
            let (mut iface, _, _) = setup(medium);
            let cx = iface.context();
            let mut socket = ipv4_locals::socket(buffer(1), buffer(0));
            assert!(!socket.can_recv());

            let mut cksumd_packet = ipv4_locals::PACKET_BYTES;
            Ipv4Packet::new_unchecked(&mut cksumd_packet).fill_checksum();

            assert_eq!(socket.recv(), Err(RecvError::Exhausted));
            assert!(socket.accepts(&ipv4_locals::HEADER_REPR));
            socket.process(cx, &ipv4_locals::HEADER_REPR, &ipv4_locals::PACKET_PAYLOAD);
            assert!(socket.can_recv());

            assert!(socket.accepts(&ipv4_locals::HEADER_REPR));
            socket.process(cx, &ipv4_locals::HEADER_REPR, &ipv4_locals::PACKET_PAYLOAD);
            assert_eq!(socket.recv(), Ok(&cksumd_packet[..]));
            assert!(!socket.can_recv());
        }
        #[cfg(feature = "proto-ipv6")]
        {
            let (mut iface, _, _) = setup(medium);
            let cx = iface.context();
            let mut socket = ipv6_locals::socket(buffer(1), buffer(0));
            assert!(!socket.can_recv());

            assert_eq!(socket.recv(), Err(RecvError::Exhausted));
            assert!(socket.accepts(&ipv6_locals::HEADER_REPR));
            socket.process(cx, &ipv6_locals::HEADER_REPR, &ipv6_locals::PACKET_PAYLOAD);
            assert!(socket.can_recv());

            assert!(socket.accepts(&ipv6_locals::HEADER_REPR));
            socket.process(cx, &ipv6_locals::HEADER_REPR, &ipv6_locals::PACKET_PAYLOAD);
            assert_eq!(socket.recv(), Ok(&ipv6_locals::PACKET_BYTES[..]));
            assert!(!socket.can_recv());
        }
    }

    #[rstest]
    #[case::ip(Medium::Ip)]
    #[case::ethernet(Medium::Ethernet)]
    #[cfg(feature = "medium-ethernet")]
    #[case::ieee802154(Medium::Ieee802154)]
    #[cfg(feature = "medium-ieee802154")]
    fn test_peek_process(#[case] medium: Medium) {
        #[cfg(feature = "proto-ipv4")]
        {
            let (mut iface, _, _) = setup(medium);
            let cx = iface.context();
            let mut socket = ipv4_locals::socket(buffer(1), buffer(0));

            let mut cksumd_packet = ipv4_locals::PACKET_BYTES;
            Ipv4Packet::new_unchecked(&mut cksumd_packet).fill_checksum();

            assert_eq!(socket.peek(), Err(RecvError::Exhausted));
            assert!(socket.accepts(&ipv4_locals::HEADER_REPR));
            socket.process(cx, &ipv4_locals::HEADER_REPR, &ipv4_locals::PACKET_PAYLOAD);

            assert!(socket.accepts(&ipv4_locals::HEADER_REPR));
            socket.process(cx, &ipv4_locals::HEADER_REPR, &ipv4_locals::PACKET_PAYLOAD);
            assert_eq!(socket.peek(), Ok(&cksumd_packet[..]));
            assert_eq!(socket.recv(), Ok(&cksumd_packet[..]));
            assert_eq!(socket.peek(), Err(RecvError::Exhausted));
        }
        #[cfg(feature = "proto-ipv6")]
        {
            let (mut iface, _, _) = setup(medium);
            let cx = iface.context();
            let mut socket = ipv6_locals::socket(buffer(1), buffer(0));

            assert_eq!(socket.peek(), Err(RecvError::Exhausted));
            assert!(socket.accepts(&ipv6_locals::HEADER_REPR));
            socket.process(cx, &ipv6_locals::HEADER_REPR, &ipv6_locals::PACKET_PAYLOAD);

            assert!(socket.accepts(&ipv6_locals::HEADER_REPR));
            socket.process(cx, &ipv6_locals::HEADER_REPR, &ipv6_locals::PACKET_PAYLOAD);
            assert_eq!(socket.peek(), Ok(&ipv6_locals::PACKET_BYTES[..]));
            assert_eq!(socket.recv(), Ok(&ipv6_locals::PACKET_BYTES[..]));
            assert_eq!(socket.peek(), Err(RecvError::Exhausted));
        }
    }

    #[test]
    fn test_doesnt_accept_wrong_proto() {
        #[cfg(feature = "proto-ipv4")]
        {
            let socket = Socket::new(
                Some(IpVersion::Ipv4),
                Some(IpProtocol::Unknown(ipv4_locals::IP_PROTO + 1)),
                buffer(1),
                buffer(1),
            );
            assert!(!socket.accepts(&ipv4_locals::HEADER_REPR));
            #[cfg(feature = "proto-ipv6")]
            assert!(!socket.accepts(&ipv6_locals::HEADER_REPR));
        }
        #[cfg(feature = "proto-ipv6")]
        {
            let socket = Socket::new(
                Some(IpVersion::Ipv6),
                Some(IpProtocol::Unknown(ipv6_locals::IP_PROTO + 1)),
                buffer(1),
                buffer(1),
            );
            assert!(!socket.accepts(&ipv6_locals::HEADER_REPR));
            #[cfg(feature = "proto-ipv4")]
            assert!(!socket.accepts(&ipv4_locals::HEADER_REPR));
        }
    }

    fn check_dispatch(socket: &mut Socket<'_>, cx: &mut Context) {
        // Check dispatch returns Ok(()) and calls the emit closure
        let mut emitted = false;
        assert_eq!(
            socket.dispatch(cx, |_, _| {
                emitted = true;
                Ok(())
            }),
            Ok::<_, ()>(())
        );
        assert!(emitted);
    }

    #[rstest]
    #[case::ip(Medium::Ip)]
    #[case::ethernet(Medium::Ethernet)]
    #[cfg(feature = "medium-ethernet")]
    #[case::ieee802154(Medium::Ieee802154)]
    #[cfg(feature = "medium-ieee802154")]
    fn test_unfiltered_sends_all(#[case] medium: Medium) {
        // Test a single unfiltered socket can send packets with different IP versions and next
        // headers
        let mut socket = Socket::new(None, None, buffer(0), buffer(2));
        #[cfg(feature = "proto-ipv4")]
        {
            let (mut iface, _, _) = setup(medium);
            let cx = iface.context();

            let mut udp_packet = ipv4_locals::PACKET_BYTES;
            Ipv4Packet::new_unchecked(&mut udp_packet).set_next_header(IpProtocol::Udp);

            assert_eq!(socket.send_slice(&udp_packet), Ok(()));
            check_dispatch(&mut socket, cx);

            let mut tcp_packet = ipv4_locals::PACKET_BYTES;
            Ipv4Packet::new_unchecked(&mut tcp_packet).set_next_header(IpProtocol::Tcp);

            assert_eq!(socket.send_slice(&tcp_packet[..]), Ok(()));
            check_dispatch(&mut socket, cx);
        }
        #[cfg(feature = "proto-ipv6")]
        {
            let (mut iface, _, _) = setup(medium);
            let cx = iface.context();

            let mut udp_packet = ipv6_locals::PACKET_BYTES;
            Ipv6Packet::new_unchecked(&mut udp_packet).set_next_header(IpProtocol::Udp);

            assert_eq!(socket.send_slice(&ipv6_locals::PACKET_BYTES), Ok(()));
            check_dispatch(&mut socket, cx);

            let mut tcp_packet = ipv6_locals::PACKET_BYTES;
            Ipv6Packet::new_unchecked(&mut tcp_packet).set_next_header(IpProtocol::Tcp);

            assert_eq!(socket.send_slice(&tcp_packet[..]), Ok(()));
            check_dispatch(&mut socket, cx);
        }
    }

    #[rstest]
    #[case::proto(IpProtocol::Icmp)]
    #[case::proto(IpProtocol::Tcp)]
    #[case::proto(IpProtocol::Udp)]
    fn test_unfiltered_accepts_all(#[case] proto: IpProtocol) {
        // Test an unfiltered socket can accept packets with different IP versions and next headers
        let socket = Socket::new(None, None, buffer(0), buffer(0));
        #[cfg(feature = "proto-ipv4")]
        {
            let header_repr = IpRepr::Ipv4(Ipv4Repr {
                src_addr: Ipv4Address::new(10, 0, 0, 1),
                dst_addr: Ipv4Address::new(10, 0, 0, 2),
                next_header: proto,
                payload_len: 4,
                hop_limit: 64,
            });
            assert!(socket.accepts(&header_repr));
        }
        #[cfg(feature = "proto-ipv6")]
        {
            let header_repr = IpRepr::Ipv6(Ipv6Repr {
                src_addr: Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
                dst_addr: Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 2),
                next_header: proto,
                payload_len: 4,
                hop_limit: 64,
            });
            assert!(socket.accepts(&header_repr));
        }
    }
}
