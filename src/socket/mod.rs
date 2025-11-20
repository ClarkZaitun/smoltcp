/*! 端点间通信

`socket`模块处理*网络端点*和*缓冲*。
它提供访问数据缓冲区的接口，以及用于填充和清空这些缓冲区的协议状态机。

这里实现的编程接口与常见的Berkeley套接字接口有很大不同。具体来说，在Berkeley接口中缓冲是隐式的：
操作系统决定缓冲区的大小并管理它。
本模块实现的接口使用显式缓冲：您决定缓冲区的大小，分配它，并让网络栈使用它。
*/

use crate::iface::Context;
use crate::time::Instant;

#[cfg(feature = "socket-dhcpv4")]
pub mod dhcpv4;
#[cfg(feature = "socket-dns")]
pub mod dns;
#[cfg(feature = "socket-icmp")]
pub mod icmp;
#[cfg(feature = "socket-raw")]
pub mod raw;
#[cfg(feature = "socket-tcp")]
pub mod tcp;
#[cfg(feature = "socket-udp")]
pub mod udp;

#[cfg(feature = "async")]
mod waker;

#[cfg(feature = "async")]
pub(crate) use self::waker::WakerRegistration;

/// 指示套接字下次应该被轮询的时间
#[derive(Debug, PartialOrd, Ord, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(crate) enum PollAt {
    /// 套接字需要立即被轮询
    Now,
    /// 套接字需要在给定的[Instant][struct.Instant]时间被轮询
    Time(Instant),
    /// 除非有外部变化，否则套接字不需要被轮询
    Ingress,
}

/// 各种IP协议类型套接字的抽象
///
/// 这个枚举抽象了各种套接字类型，允许它们被存储在集合中。它提供了轮询套接字的通用接口。
/// 要将 `Socket` 值向下转换为具体套接字，请使用 [AnySocket] trait，
/// 例如，要获取 `udp::Socket`，请调用 `udp::Socket::downcast(socket)`。
///
/// 通常使用 [SocketSet::get] 更方便。
///
/// [AnySocket]: trait.AnySocket.html
/// [SocketSet::get]: struct.SocketSet.html#method.get
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum Socket<'a> {
    #[cfg(feature = "socket-raw")]
    Raw(raw::Socket<'a>),
    #[cfg(feature = "socket-icmp")]
    Icmp(icmp::Socket<'a>),
    #[cfg(feature = "socket-udp")]
    Udp(udp::Socket<'a>),
    #[cfg(feature = "socket-tcp")]
    Tcp(tcp::Socket<'a>),
    #[cfg(feature = "socket-dhcpv4")]
    Dhcpv4(dhcpv4::Socket<'a>),
    #[cfg(feature = "socket-dns")]
    Dns(dns::Socket<'a>),
}

impl<'a> Socket<'a> {
    /// 返回套接字的下次轮询时间
    ///
    /// 另见 [SocketSet::poll_at]
    pub(crate) fn poll_at(&self, cx: &mut Context) -> PollAt {
        match self {
            #[cfg(feature = "socket-raw")]
            Socket::Raw(s) => s.poll_at(cx),
            #[cfg(feature = "socket-icmp")]
            Socket::Icmp(s) => s.poll_at(cx),
            #[cfg(feature = "socket-udp")]
            Socket::Udp(s) => s.poll_at(cx),
            #[cfg(feature = "socket-tcp")]
            Socket::Tcp(s) => s.poll_at(cx),
            #[cfg(feature = "socket-dhcpv4")]
            Socket::Dhcpv4(s) => s.poll_at(cx),
            #[cfg(feature = "socket-dns")]
            Socket::Dns(s) => s.poll_at(cx),
        }
    }
}

/// 套接字的转换trait
pub trait AnySocket<'a> {
    fn upcast(self) -> Socket<'a>;
    fn downcast<'c>(socket: &'c Socket<'a>) -> Option<&'c Self>
    where
        Self: Sized;
    fn downcast_mut<'c>(socket: &'c mut Socket<'a>) -> Option<&'c mut Self>
    where
        Self: Sized;
}

macro_rules! from_socket {
    ($socket:ty, $variant:ident) => {
        impl<'a> AnySocket<'a> for $socket {
            fn upcast(self) -> Socket<'a> {
                Socket::$variant(self)
            }

            fn downcast<'c>(socket: &'c Socket<'a>) -> Option<&'c Self> {
                #[allow(unreachable_patterns)]
                match socket {
                    Socket::$variant(socket) => Some(socket),
                    _ => None,
                }
            }

            fn downcast_mut<'c>(socket: &'c mut Socket<'a>) -> Option<&'c mut Self> {
                #[allow(unreachable_patterns)]
                match socket {
                    Socket::$variant(socket) => Some(socket),
                    _ => None,
                }
            }
        }
    };
}

#[cfg(feature = "socket-raw")]
from_socket!(raw::Socket<'a>, Raw);
#[cfg(feature = "socket-icmp")]
from_socket!(icmp::Socket<'a>, Icmp);
#[cfg(feature = "socket-udp")]
from_socket!(udp::Socket<'a>, Udp);
#[cfg(feature = "socket-tcp")]
from_socket!(tcp::Socket<'a>, Tcp);
#[cfg(feature = "socket-dhcpv4")]
from_socket!(dhcpv4::Socket<'a>, Dhcpv4);
#[cfg(feature = "socket-dns")]
from_socket!(dns::Socket<'a>, Dns);
