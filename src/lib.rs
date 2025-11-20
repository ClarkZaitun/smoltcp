#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![deny(unsafe_code)]

//! _smoltcp_ 库采用分层架构，各层对应不同级别的API抽象。典型应用程序通常只使用最高层；
//! 然而，smoltcp的目标不仅是为编写应用程序提供简单接口，还要成为网络原语的工具箱，
//! 因此每一层都完全暴露并有详细文档。
//!
//! 在讨论网络栈和分层时，经常会提到[OSI模型][osi]。smoltcp不试图遵循OSI模型，因为它不适用于TCP/IP。
//!
//! # 套接字层
//! 套接字层API在模块[socket](socket/index.html)中提供；目前提供原始套接字、ICMP、TCP和UDP套接字。
//! 套接字API提供常用原语，但由于后者并非为无堆分配使用而设计，因此必然在多方面与
//! [Berkeley套接字API][berk]有所不同。
//!
//! 套接字层提供缓冲、数据包构造和验证，以及（对于有状态套接字）状态机，但它是接口无关的。
//! 应用程序必须将套接字与网络接口一起使用。
//!
//! # 接口层
//! 接口层API在模块[iface](iface/index.html)中提供；目前提供以太网接口。
//!
//! 接口层处理控制消息、物理寻址和邻居发现。它负责在套接字之间路由数据包。
//!
//! # 物理层
//! 物理层API在模块[phy](phy/index.html)中提供；目前提供原始套接字和TAP接口。
//! 此外，还提供了两个_中间件_接口：_跟踪设备_，它打印数据包的可读表示，
//! 和_故障注入设备_，它在传输和接收的数据包序列中随机引入错误。
//!
//! 物理层处理与平台特定网络设备的交互。
//!
//! # 线路层
//! 与较高层不同，典型应用程序不会使用线路层API。然而它们是smoltcp的基石，其他一切都构建在它们之上。
//!
//! 线路层API的设计原则是"使非法状态无法表示"。如果可以构造线路层对象，那么它也可以从较低层解析或发出到较低层。
//!
//! 线路层API还提供类似_tcpdump_的漂亮打印功能。
//!
//! ## 表示层
//! 表示层API在模块[wire]中提供。
//!
//! 表示层的存在是为了减少原始数据包的状态空间。原始数据包可能以多种方式毫无意义：
//! 无效校验和、不可能的标志组合、超出边界的字段指针、无意义的选项...表示层会去除所有这些，
//! 以及smoltcp不支持的任何特性。
//!
//! ## 数据包层
//! 数据包层API也在模块[wire]中提供。
//!
//! 数据包层的存在是为了提供比将数据包视为字节序列更有结构的方式来处理数据包。
//! 除了为安全访问字段所必需的情况外，它不对数据包的内容做出判断，并努力实现曾经定义的每个特性，
//! 以确保当表示层无法理解数据包时，它仍能正确且完整地记录。
//!
//! # Minimum Supported Rust Version (MSRV)
//!
//! This crate is guaranteed to compile on stable Rust 1.87 and up with any valid set of features.
//! It *might* compile on older versions but that may change in any new patch release.
//!
//! The exception is when using the `defmt` feature, in which case `defmt`'s MSRV applies, which
//! is higher.
//!
//! [wire]: wire/index.html
//! [osi]: https://en.wikipedia.org/wiki/OSI_model
//! [berk]: https://en.wikipedia.org/wiki/Berkeley_sockets

/* XXX compiler bug
#![cfg(not(any(feature = "socket-raw",
               feature = "socket-udp",
               feature = "socket-tcp")))]
compile_error!("at least one socket needs to be enabled"); */

#![allow(clippy::match_like_matches_macro)]
#![allow(clippy::redundant_field_names)]
#![allow(clippy::identity_op)]
#![allow(clippy::option_map_unit_fn)]
#![allow(clippy::unit_arg)]
#![allow(clippy::new_without_default)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(not(any(
    feature = "proto-ipv4",
    feature = "proto-ipv6",
    feature = "proto-sixlowpan"
)))]
compile_error!(
    "You must enable at least one of the following features: proto-ipv4, proto-ipv6, proto-sixlowpan"
);

#[cfg(all(
    feature = "socket",
    not(any(
        feature = "socket-raw",
        feature = "socket-udp",
        feature = "socket-tcp",
        feature = "socket-icmp",
        feature = "socket-dhcpv4",
        feature = "socket-dns",
    ))
))]
compile_error!(
    "If you enable the socket feature, you must enable at least one of the following features: socket-raw, socket-udp, socket-tcp, socket-icmp, socket-dhcpv4, socket-dns"
);

#[cfg(all(
    feature = "socket",
    not(any(
        feature = "medium-ethernet",
        feature = "medium-ip",
        feature = "medium-ieee802154",
    ))
))]
compile_error!(
    "If you enable the socket feature, you must enable at least one of the following features: medium-ip, medium-ethernet, medium-ieee802154"
);

#[cfg(all(feature = "defmt", feature = "log"))]
compile_error!("You must enable at most one of the following features: defmt, log");

#[macro_use]
mod macros;
mod parsers;
mod rand;

#[cfg(test)]
pub mod config {
    #![allow(unused)]
    pub const ASSEMBLER_MAX_SEGMENT_COUNT: usize = 4;
    pub const DNS_MAX_NAME_SIZE: usize = 255;
    pub const DNS_MAX_RESULT_COUNT: usize = 1;
    pub const DNS_MAX_SERVER_COUNT: usize = 1;
    pub const FRAGMENTATION_BUFFER_SIZE: usize = 4096;
    pub const IFACE_MAX_ADDR_COUNT: usize = 8;
    pub const IFACE_MAX_MULTICAST_GROUP_COUNT: usize = 4;
    pub const IFACE_MAX_ROUTE_COUNT: usize = 4;
    pub const IFACE_MAX_SIXLOWPAN_ADDRESS_CONTEXT_COUNT: usize = 4;
    pub const IFACE_NEIGHBOR_CACHE_COUNT: usize = 3;
    pub const REASSEMBLY_BUFFER_COUNT: usize = 4;
    pub const REASSEMBLY_BUFFER_SIZE: usize = 1500;
    pub const RPL_RELATIONS_BUFFER_COUNT: usize = 16;
    pub const RPL_PARENTS_BUFFER_COUNT: usize = 8;
    pub const IPV6_HBH_MAX_OPTIONS: usize = 4;
}

#[cfg(not(test))]
pub mod config {
    #![allow(unused)]
    include!(concat!(env!("OUT_DIR"), "/config.rs"));
}

#[cfg(any(
    feature = "medium-ethernet",
    feature = "medium-ip",
    feature = "medium-ieee802154"
))]
pub mod iface;

pub mod phy;
#[cfg(feature = "socket")]
pub mod socket;
pub mod storage;
pub mod time;
pub mod wire;

#[cfg(all(
    test,
    any(
        feature = "medium-ethernet",
        feature = "medium-ip",
        feature = "medium-ieee802154"
    )
))]
mod tests;
