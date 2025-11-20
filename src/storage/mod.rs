/*! 专用容器模块。

`storage` 模块为其他模块提供容器支持。
这些容器支持预分配内存（无需 `std` 或 `alloc` crate）和堆分配内存。
*/

mod assembler;
mod packet_buffer;
mod ring_buffer;

pub use self::assembler::Assembler;
pub use self::packet_buffer::{PacketBuffer, PacketMetadata};
pub use self::ring_buffer::RingBuffer;

/// 将值设置为已知状态的特征。
///
/// Default 的本地替代版本。
pub trait Resettable {
    fn reset(&mut self);
}

/// 向已满缓冲区入队时返回的错误。
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Full;

/// 从空缓冲区出队时返回的错误。
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Empty;
