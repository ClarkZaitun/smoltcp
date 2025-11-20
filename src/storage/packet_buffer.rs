use managed::ManagedSlice;

use crate::storage::{Full, RingBuffer};

use super::Empty;

/// 数据包的大小和头部信息。
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PacketMetadata<H> {
    size: usize,
    header: Option<H>,
}

impl<H> PacketMetadata<H> {
    /// 空数据包描述。
    pub const EMPTY: PacketMetadata<H> = PacketMetadata {
        size: 0,
        header: None,
    };

    fn padding(size: usize) -> PacketMetadata<H> {
        PacketMetadata {
            size: size,
            header: None,
        }
    }

    fn packet(size: usize, header: H) -> PacketMetadata<H> {
        PacketMetadata {
            size: size,
            header: Some(header),
        }
    }

    fn is_padding(&self) -> bool {
        self.header.is_none()
    }
}

/// UDP数据包环形缓冲区。
#[derive(Debug)]
pub struct PacketBuffer<'a, H: 'a> {
    metadata_ring: RingBuffer<'a, PacketMetadata<H>>,
    payload_ring: RingBuffer<'a, u8>,
}

impl<'a, H> PacketBuffer<'a, H> {
    /// 使用提供的元数据和有效载荷存储创建新的数据包缓冲区。
    ///
    /// 元数据存储限制缓冲区中的最大数据包_数量_，
    /// 有效载荷存储限制数据包的最大_总大小_。
    pub fn new<MS, PS>(metadata_storage: MS, payload_storage: PS) -> PacketBuffer<'a, H>
    where
        MS: Into<ManagedSlice<'a, PacketMetadata<H>>>,
        PS: Into<ManagedSlice<'a, u8>>,
    {
        PacketBuffer {
            metadata_ring: RingBuffer::new(metadata_storage),
            payload_ring: RingBuffer::new(payload_storage),
        }
    }

    /// 查询缓冲区是否为空。
    pub fn is_empty(&self) -> bool {
        self.metadata_ring.is_empty()
    }

    /// 查询缓冲区是否已满。
    pub fn is_full(&self) -> bool {
        self.metadata_ring.is_full()
    }

    // 目前没有 enqueue_with() 是因为在失败情况下管理填充的复杂性。

    /// 将具有给定头部的单个数据包入队到缓冲区，
    /// 并返回对其有效载荷的引用，如果缓冲区已满
    /// 则返回 `Err(Full)`。
    pub fn enqueue(&mut self, size: usize, header: H) -> Result<&mut [u8], Full> {
        if self.payload_ring.capacity() < size || self.metadata_ring.is_full() {
            return Err(Full);
        }

        // 环形缓冲区当前为空。清除它（重置 `read_at`）以最大化
        // 连续空间。
        if self.payload_ring.is_empty() {
            self.payload_ring.clear();
        }

        let window = self.payload_ring.window();
        let contig_window = self.payload_ring.contiguous_window();

        if window < size {
            return Err(Full);
        } else if contig_window < size {
            if window - contig_window < size {
                // 缓冲区长度大于当前连续窗口，
                // 并且大于添加必要填充以环绕到
                // 环形缓冲区开始后的连续窗口。
                return Err(Full);
            } else {
                // 在环形缓冲区末尾添加填充，使得
                // 连续窗口位于环形缓冲区的开始处。
                *self.metadata_ring.enqueue_one()? = PacketMetadata::padding(contig_window);
                // 注意（丢弃）：函数不会写入结果
                // 入队的填充缓冲区位置
                let _buf_enqueued = self.payload_ring.enqueue_many(contig_window);
            }
        }

        *self.metadata_ring.enqueue_one()? = PacketMetadata::packet(size, header);

        let payload_buf = self.payload_ring.enqueue_many(size);
        debug_assert!(payload_buf.len() == size);
        Ok(payload_buf)
    }

    /// 使用缓冲区中足够大以容纳 `max_size` 字节的数据包调用 `f`。
    /// 数据包被缩小到 `f` 返回的大小并入队到缓冲区。
    pub fn enqueue_with_infallible<'b, F>(
        &'b mut self,
        max_size: usize,
        header: H,
        f: F,
    ) -> Result<usize, Full>
    where
        F: FnOnce(&'b mut [u8]) -> usize,
    {
        if self.payload_ring.capacity() < max_size || self.metadata_ring.is_full() {
            return Err(Full);
        }

        let window = self.payload_ring.window();
        let contig_window = self.payload_ring.contiguous_window();

        if window < max_size {
            return Err(Full);
        } else if contig_window < max_size {
            if window - contig_window < max_size {
                // The buffer length is larger than the current contiguous window
                // and is larger than the contiguous window will be after adding
                // the padding necessary to circle around to the beginning of the
                // ring buffer.
                return Err(Full);
            } else {
                // Add padding to the end of the ring buffer so that the
                // contiguous window is at the beginning of the ring buffer.
                *self.metadata_ring.enqueue_one()? = PacketMetadata::padding(contig_window);
                // note(discard): function does not write to the result
                // enqueued padding buffer location
                let _buf_enqueued = self.payload_ring.enqueue_many(contig_window);
            }
        }

        let (size, _) = self
            .payload_ring
            .enqueue_many_with(|data| (f(&mut data[..max_size]), ()));

        *self.metadata_ring.enqueue_one()? = PacketMetadata::packet(size, header);

        Ok(size)
    }

    fn dequeue_padding(&mut self) {
        let _ = self.metadata_ring.dequeue_one_with(|metadata| {
            if metadata.is_padding() {
                // 注意（丢弃）：函数不使用出队填充字节的值
                let _buf_dequeued = self.payload_ring.dequeue_many(metadata.size);
                Ok(()) // 出队元数据
            } else {
                Err(()) // 不出队元数据
            }
        });
    }

    /// 使用缓冲区中的单个数据包调用 `f`，如果 `f`
    /// 返回成功则出队该数据包，如果缓冲区为空则返回 `Err(EmptyError)`。
    pub fn dequeue_with<'c, R, E, F>(&'c mut self, f: F) -> Result<Result<R, E>, Empty>
    where
        F: FnOnce(&mut H, &'c mut [u8]) -> Result<R, E>,
    {
        self.dequeue_padding();

        self.metadata_ring.dequeue_one_with(|metadata| {
            self.payload_ring
                .dequeue_many_with(|payload_buf| {
                    debug_assert!(payload_buf.len() >= metadata.size);

                    match f(
                        metadata.header.as_mut().unwrap(),
                        &mut payload_buf[..metadata.size],
                    ) {
                        Ok(val) => (metadata.size, Ok(val)),
                        Err(err) => (0, Err(err)),
                    }
                })
                .1
        })
    }

    /// 从缓冲区出队单个数据包，并返回对其有效载荷
    /// 以及头部的引用，如果缓冲区为空则返回 `Err(Error::Exhausted)`。
    pub fn dequeue(&mut self) -> Result<(H, &mut [u8]), Empty> {
        self.dequeue_padding();

        let meta = self.metadata_ring.dequeue_one()?;

        let payload_buf = self.payload_ring.dequeue_many(meta.size);
        debug_assert!(payload_buf.len() == meta.size);
        Ok((meta.header.take().unwrap(), payload_buf))
    }

    /// 从缓冲区中窥视单个数据包而不移除它，并返回对其
    /// 有效载荷以及头部的引用，如果缓冲区为空则返回 `Err(Error:Exhausted)`。
    ///
    /// 此函数在其他方面与 [dequeue](#method.dequeue) 行为相同。
    pub fn peek(&mut self) -> Result<(&H, &[u8]), Empty> {
        self.dequeue_padding();

        if let Some(metadata) = self.metadata_ring.get_allocated(0, 1).first() {
            Ok((
                metadata.header.as_ref().unwrap(),
                self.payload_ring.get_allocated(0, metadata.size),
            ))
        } else {
            Err(Empty)
        }
    }

    /// 返回可以存储的最大数据包数量。
    pub fn packet_capacity(&self) -> usize {
        self.metadata_ring.capacity()
    }

    /// 返回有效载荷环形缓冲区中的最大字节数。
    pub fn payload_capacity(&self) -> usize {
        self.payload_ring.capacity()
    }

    /// 返回有效载荷环形缓冲区中当前的字节数。
    pub fn payload_bytes_count(&self) -> usize {
        self.payload_ring.len()
    }

    /// 重置数据包缓冲区并清除任何已暂存的。
    #[allow(unused)]
    pub(crate) fn reset(&mut self) {
        self.payload_ring.clear();
        self.metadata_ring.clear();
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn buffer() -> PacketBuffer<'static, ()> {
        PacketBuffer::new(vec![PacketMetadata::EMPTY; 4], vec![0u8; 16])
    }

    #[test]
    fn test_simple() {
        let mut buffer = buffer();
        buffer.enqueue(6, ()).unwrap().copy_from_slice(b"abcdef");
        assert_eq!(buffer.enqueue(16, ()), Err(Full));
        assert_eq!(buffer.metadata_ring.len(), 1);
        assert_eq!(buffer.dequeue().unwrap().1, &b"abcdef"[..]);
        assert_eq!(buffer.dequeue(), Err(Empty));
    }

    #[test]
    fn test_peek() {
        let mut buffer = buffer();
        assert_eq!(buffer.peek(), Err(Empty));
        buffer.enqueue(6, ()).unwrap().copy_from_slice(b"abcdef");
        assert_eq!(buffer.metadata_ring.len(), 1);
        assert_eq!(buffer.peek().unwrap().1, &b"abcdef"[..]);
        assert_eq!(buffer.dequeue().unwrap().1, &b"abcdef"[..]);
        assert_eq!(buffer.peek(), Err(Empty));
    }

    #[test]
    fn test_padding() {
        let mut buffer = buffer();
        assert!(buffer.enqueue(6, ()).is_ok());
        assert!(buffer.enqueue(8, ()).is_ok());
        assert!(buffer.dequeue().is_ok());
        buffer.enqueue(4, ()).unwrap().copy_from_slice(b"abcd");
        assert_eq!(buffer.metadata_ring.len(), 3);
        assert!(buffer.dequeue().is_ok());

        assert_eq!(buffer.dequeue().unwrap().1, &b"abcd"[..]);
        assert_eq!(buffer.metadata_ring.len(), 0);
    }

    #[test]
    fn test_padding_with_large_payload() {
        let mut buffer = buffer();
        assert!(buffer.enqueue(12, ()).is_ok());
        assert!(buffer.dequeue().is_ok());
        buffer
            .enqueue(12, ())
            .unwrap()
            .copy_from_slice(b"abcdefghijkl");
    }

    #[test]
    fn test_dequeue_with() {
        let mut buffer = buffer();
        assert!(buffer.enqueue(6, ()).is_ok());
        assert!(buffer.enqueue(8, ()).is_ok());
        assert!(buffer.dequeue().is_ok());
        buffer.enqueue(4, ()).unwrap().copy_from_slice(b"abcd");
        assert_eq!(buffer.metadata_ring.len(), 3);
        assert!(buffer.dequeue().is_ok());

        assert!(matches!(
            buffer.dequeue_with(|_, _| Result::<(), u32>::Err(123)),
            Ok(Err(_))
        ));
        assert_eq!(buffer.metadata_ring.len(), 1);

        assert!(
            buffer
                .dequeue_with(|&mut (), payload| {
                    assert_eq!(payload, &b"abcd"[..]);
                    Result::<(), ()>::Ok(())
                })
                .is_ok()
        );
        assert_eq!(buffer.metadata_ring.len(), 0);
    }

    #[test]
    fn test_metadata_full_empty() {
        let mut buffer = buffer();
        assert!(buffer.is_empty());
        assert!(!buffer.is_full());
        assert!(buffer.enqueue(1, ()).is_ok());
        assert!(!buffer.is_empty());
        assert!(buffer.enqueue(1, ()).is_ok());
        assert!(buffer.enqueue(1, ()).is_ok());
        assert!(!buffer.is_full());
        assert!(!buffer.is_empty());
        assert!(buffer.enqueue(1, ()).is_ok());
        assert!(buffer.is_full());
        assert!(!buffer.is_empty());
        assert_eq!(buffer.metadata_ring.len(), 4);
        assert_eq!(buffer.enqueue(1, ()), Err(Full));
    }

    #[test]
    fn test_window_too_small() {
        let mut buffer = buffer();
        assert!(buffer.enqueue(4, ()).is_ok());
        assert!(buffer.enqueue(8, ()).is_ok());
        assert!(buffer.dequeue().is_ok());
        assert_eq!(buffer.enqueue(16, ()), Err(Full));
        assert_eq!(buffer.metadata_ring.len(), 1);
    }

    #[test]
    fn test_contiguous_window_too_small() {
        let mut buffer = buffer();
        assert!(buffer.enqueue(4, ()).is_ok());
        assert!(buffer.enqueue(8, ()).is_ok());
        assert!(buffer.dequeue().is_ok());
        assert_eq!(buffer.enqueue(8, ()), Err(Full));
        assert_eq!(buffer.metadata_ring.len(), 1);
    }

    #[test]
    fn test_contiguous_window_wrap() {
        let mut buffer = buffer();
        assert!(buffer.enqueue(15, ()).is_ok());
        assert!(buffer.dequeue().is_ok());
        assert!(buffer.enqueue(16, ()).is_ok());
    }

    #[test]
    fn test_capacity_too_small() {
        let mut buffer = buffer();
        assert_eq!(buffer.enqueue(32, ()), Err(Full));
    }

    #[test]
    fn test_contig_window_prioritized() {
        let mut buffer = buffer();
        assert!(buffer.enqueue(4, ()).is_ok());
        assert!(buffer.dequeue().is_ok());
        assert!(buffer.enqueue(5, ()).is_ok());
    }

    #[test]
    fn clear() {
        let mut buffer = buffer();

        // Ensure enqueuing data in the buffer fills it somewhat.
        assert!(buffer.is_empty());
        assert!(buffer.enqueue(6, ()).is_ok());

        // Ensure that resetting the buffer causes it to be empty.
        assert!(!buffer.is_empty());
        buffer.reset();
        assert!(buffer.is_empty());
    }
}
