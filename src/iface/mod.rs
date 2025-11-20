/*! 网络接口逻辑。

`iface` 模块处理*网络接口*。它过滤进入的帧，
提供硬件地址的查找和缓存，并处理管理数据包。
*/

mod fragmentation;
mod interface;
#[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
mod neighbor;
mod route;
#[cfg(feature = "proto-rpl")]
mod rpl;
mod socket_meta;
mod socket_set;

mod packet;

#[cfg(feature = "multicast")]
pub use self::interface::multicast::MulticastError;
pub use self::interface::{
    Config, Interface, InterfaceInner as Context, PollIngressSingleResult, PollResult,
};

pub use self::route::{Route, RouteTableFull, Routes};
pub use self::socket_set::{SocketHandle, SocketSet, SocketStorage};
