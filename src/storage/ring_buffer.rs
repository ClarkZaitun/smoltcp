// 环形缓冲区中的一些函数被标记为 #[must_use]。这表示这些函数可能有副作用，
// 该特性由 [RFC 1940] 实现。
// [RFC 1940]: https://github.com/rust-lang/rust/issues/43302

use core::cmp;
use managed::ManagedSlice;

use crate::storage::Resettable;

use super::{Empty, Full};

/// 环形缓冲区。
///
/// 这个环形缓冲区实现提供了多种交互方式：
///
///   * 从缓冲区的对应侧入队或出队单个元素；
///   * 从缓冲区的对应侧入队或出队元素切片；
///   * 直接访问已分配和未分配的区域。
///
/// 它也是零拷贝的；所有方法都提供对缓冲区存储的引用。
/// 注意所有引用都是可变的；允许就地处理被认为比防止意外修改更重要。
///
/// 这个实现既适用于简单的用途，如UDP数据包的FIFO队列，也适用于高级用途，如TCP重组缓冲区。
#[derive(Debug)]
pub struct RingBuffer<'a, T: 'a> {
    storage: ManagedSlice<'a, T>,  // 存储元素的托管切片
    read_at: usize,                   // 读取位置索引
    length: usize,                    // 当前长度
}

impl<'a, T: 'a> RingBuffer<'a, T> {
    /// 使用给定的存储创建环形缓冲区。
    ///
    /// 创建期间，`storage` 中的每个元素都会被重置。
    pub fn new<S>(storage: S) -> RingBuffer<'a, T>
    where
        S: Into<ManagedSlice<'a, T>>,
    {
        RingBuffer {
            storage: storage.into(),
            read_at: 0,
            length: 0,
        }
    }

    /// 清空环形缓冲区。
    pub fn clear(&mut self) {
        self.read_at = 0;
        self.length = 0;
    }

    /// 返回环形缓冲区中的最大元素数量。
    pub fn capacity(&self) -> usize {
        self.storage.len()
    }

    /// 清空环形缓冲区，并重置每个元素。
    pub fn reset(&mut self)
    where
        T: Resettable,
    {
        self.clear();
        for elem in self.storage.iter_mut() {
            elem.reset();
        }
    }

    /// 返回环形缓冲区中当前的元素数量。
    pub fn len(&self) -> usize {
        self.length
    }

    /// 返回可以添加到环形缓冲区的元素数量。
    pub fn window(&self) -> usize {
        self.capacity() - self.len()
    }

    /// 返回在不绕回的情况下可以添加到缓冲区的最大元素数量
    /// （即在单次 `enqueue_many` 调用中）。
    pub fn contiguous_window(&self) -> usize {
        cmp::min(self.window(), self.capacity() - self.get_idx(self.length))
    }

    /// 查询缓冲区是否为空。
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// 查询缓冲区是否已满。
    pub fn is_full(&self) -> bool {
        self.window() == 0
    }

    /// `(self.read + idx) % self.capacity()` 的简写形式，带有
    /// 确保容量不为零的额外检查。
    fn get_idx(&self, idx: usize) -> usize {
        let len = self.capacity();
        if len > 0 {
            (self.read_at + idx) % len
        } else {
            0
        }
    }

    /// `(self.read + idx) % self.capacity()` 的简写形式，没有
    /// 确保容量不为零的额外检查。
    fn get_idx_unchecked(&self, idx: usize) -> usize {
        (self.read_at + idx) % self.capacity()
    }
}

/// 这是"离散"环形缓冲区接口：它操作单个元素，
/// 边界条件（空/满）是错误。
impl<'a, T: 'a> RingBuffer<'a, T> {
    /// 使用单个缓冲区元素调用 `f`，如果 `f` 返回成功则入队该元素，
    /// 如果缓冲区已满则返回 `Err(Full)`。
    pub fn enqueue_one_with<'b, R, E, F>(&'b mut self, f: F) -> Result<Result<R, E>, Full>
    where
        F: FnOnce(&'b mut T) -> Result<R, E>,
    {
        if self.is_full() {
            return Err(Full);
        }

        let index = self.get_idx_unchecked(self.length);
        let res = f(&mut self.storage[index]);
        if res.is_ok() {
            self.length += 1;
        }
        Ok(res)
    }

    /// 将单个元素入队到缓冲区，并返回对它的引用，
    /// 如果缓冲区已满则返回 `Err(Full)`。
    ///
    /// 这个函数是 `ring_buf.enqueue_one_with(Ok)` 的快捷方式。
    pub fn enqueue_one(&mut self) -> Result<&mut T, Full> {
        self.enqueue_one_with(Ok)?
    }

    /// 使用单个缓冲区元素调用 `f`，如果 `f` 返回成功则出队该元素，
    /// 如果缓冲区为空则返回 `Err(Empty)`。
    pub fn dequeue_one_with<'b, R, E, F>(&'b mut self, f: F) -> Result<Result<R, E>, Empty>
    where
        F: FnOnce(&'b mut T) -> Result<R, E>,
    {
        if self.is_empty() {
            return Err(Empty);
        }

        let next_at = self.get_idx_unchecked(1);
        let res = f(&mut self.storage[self.read_at]);

        if res.is_ok() {
            self.length -= 1;
            self.read_at = next_at;
        }
        Ok(res)
    }

    /// 从缓冲区出队一个元素，并返回对它的引用，
    /// 如果缓冲区为空则返回 `Err(Empty)`。
    ///
    /// 这个函数是 `ring_buf.dequeue_one_with(Ok)` 的快捷方式。
    pub fn dequeue_one(&mut self) -> Result<&mut T, Empty> {
        self.dequeue_one_with(Ok)?
    }
}

/// 这是"连续"环形缓冲区接口：它使用元素切片操作，
/// 边界条件（空/满）简单地导致空切片。
impl<'a, T: 'a> RingBuffer<'a, T> {
    /// 使用最大的未分配缓冲区元素连续切片调用 `f`，
    /// 并将 `f` 返回的元素数量入队。
    ///
    /// # Panics
    /// 如果 `f` 返回的元素数量大于传入的切片大小，
    /// 此函数会 panic。
    pub fn enqueue_many_with<'b, R, F>(&'b mut self, f: F) -> (usize, R)
    where
        F: FnOnce(&'b mut [T]) -> (usize, R),
    {
        if self.length == 0 {
            // 环形缓冲区当前为空。重置 `read_at` 以优化
            // 连续空间。
            self.read_at = 0;
        }

        let write_at = self.get_idx(self.length);
        let max_size = self.contiguous_window();
        let (size, result) = f(&mut self.storage[write_at..write_at + max_size]);
        assert!(size <= max_size);
        self.length += size;
        (size, result)
    }

    /// 将给定大小的元素切片入队到缓冲区，
    /// 并返回对它们的引用。
    ///
    /// 如果缓冲区中的空闲空间不是连续的，
    /// 此函数可能返回一个小于给定大小的切片。
    #[must_use]
    pub fn enqueue_many(&mut self, size: usize) -> &mut [T] {
        self.enqueue_many_with(|buf| {
            let size = cmp::min(size, buf.len());
            (size, &mut buf[..size])
        })
        .1
    }

    /// 从给定切片中尽可能多地将元素入队到缓冲区，
    /// 并返回能够容纳的元素数量。
    #[must_use]
    pub fn enqueue_slice(&mut self, data: &[T]) -> usize
    where
        T: Copy,
    {
        let (size_1, data) = self.enqueue_many_with(|buf| {
            let size = cmp::min(buf.len(), data.len());
            buf[..size].copy_from_slice(&data[..size]);
            (size, &data[size..])
        });
        let (size_2, ()) = self.enqueue_many_with(|buf| {
            let size = cmp::min(buf.len(), data.len());
            buf[..size].copy_from_slice(&data[..size]);
            (size, ())
        });
        size_1 + size_2
    }

    /// 使用最大的已分配缓冲区元素连续切片调用 `f`，
    /// 并将 `f` 返回的元素数量出队。
    ///
    /// # Panics
    /// 如果 `f` 返回的元素数量大于传入的切片大小，
    /// 此函数会 panic。
    pub fn dequeue_many_with<'b, R, F>(&'b mut self, f: F) -> (usize, R)
    where
        F: FnOnce(&'b mut [T]) -> (usize, R),
    {
        let capacity = self.capacity();
        let max_size = cmp::min(self.len(), capacity - self.read_at);
        let (size, result) = f(&mut self.storage[self.read_at..self.read_at + max_size]);
        assert!(size <= max_size);
        self.read_at = if capacity > 0 {
            (self.read_at + size) % capacity
        } else {
            0
        };
        self.length -= size;
        (size, result)
    }

    /// 从缓冲区出队给定大小的元素切片，
    /// 并返回对它们的引用。
    ///
    /// 如果缓冲区中的已分配空间不是连续的，
    /// 此函数可能返回一个小于给定大小的切片。
    #[must_use]
    pub fn dequeue_many(&mut self, size: usize) -> &mut [T] {
        self.dequeue_many_with(|buf| {
            let size = cmp::min(size, buf.len());
            (size, &mut buf[..size])
        })
        .1
    }

    /// 从缓冲区中尽可能多地将元素出队到给定切片中，
    /// 并返回能够容纳的元素数量。
    #[must_use]
    pub fn dequeue_slice(&mut self, data: &mut [T]) -> usize
    where
        T: Copy,
    {
        let (size_1, data) = self.dequeue_many_with(|buf| {
            let size = cmp::min(buf.len(), data.len());
            data[..size].copy_from_slice(&buf[..size]);
            (size, &mut data[size..])
        });
        let (size_2, ()) = self.dequeue_many_with(|buf| {
            let size = cmp::min(buf.len(), data.len());
            data[..size].copy_from_slice(&buf[..size]);
            (size, ())
        });
        size_1 + size_2
    }
}

/// 这是"随机访问"环形缓冲区接口：它使用元素切片操作，
/// 并允许访问缓冲区中不与其头部或尾部相邻的元素。
impl<'a, T: 'a> RingBuffer<'a, T> {
    /// 返回从给定偏移量（越过最后一个已分配元素）开始的、
    /// 最大的未分配缓冲区元素连续切片，直到给定大小。
    #[must_use]
    pub fn get_unallocated(&mut self, offset: usize, mut size: usize) -> &mut [T] {
        let start_at = self.get_idx(self.length + offset);
        // 我们不能访问超过未分配数据末尾的位置。
        if offset > self.window() {
            return &mut [];
        }
        // 我们不能入队超过空闲空间的数量。
        let clamped_window = self.window() - offset;
        if size > clamped_window {
            size = clamped_window
        }
        // 我们不能连续地入队超过存储末尾的位置。
        let until_end = self.capacity() - start_at;
        if size > until_end {
            size = until_end
        }

        &mut self.storage[start_at..start_at + size]
    }

    /// 从给定切片中将元素写入未分配缓冲区元素，
    /// 从给定偏移量（越过最后一个已分配元素）开始，
    /// 并返回写入的数量。
    #[must_use]
    pub fn write_unallocated(&mut self, offset: usize, data: &[T]) -> usize
    where
        T: Copy,
    {
        let (size_1, offset, data) = {
            let slice = self.get_unallocated(offset, data.len());
            let slice_len = slice.len();
            slice.copy_from_slice(&data[..slice_len]);
            (slice_len, offset + slice_len, &data[slice_len..])
        };
        let size_2 = {
            let slice = self.get_unallocated(offset, data.len());
            let slice_len = slice.len();
            slice.copy_from_slice(&data[..slice_len]);
            slice_len
        };
        size_1 + size_2
    }

    /// 入队给定数量的未分配缓冲区元素。
    ///
    /// # Panics
    /// 如果给定的元素数量超过未分配元素的数量，则 panic。
    pub fn enqueue_unallocated(&mut self, count: usize) {
        assert!(count <= self.window());
        self.length += count;
    }

    /// 返回从给定偏移量（越过第一个已分配元素）开始的、
    /// 最大的已分配缓冲区元素连续切片，直到给定大小。
    #[must_use]
    pub fn get_allocated(&self, offset: usize, mut size: usize) -> &[T] {
        let start_at = self.get_idx(offset);
        // 我们不能读取超过已分配数据末尾的位置。
        if offset > self.length {
            return &mut [];
        }
        // 我们不能读取超过我们已分配的数量。
        let clamped_length = self.length - offset;
        if size > clamped_length {
            size = clamped_length
        }
        // 我们不能连续地出队超过存储末尾的位置。
        let until_end = self.capacity() - start_at;
        if size > until_end {
            size = until_end
        }

        &self.storage[start_at..start_at + size]
    }

    /// Read as many elements from allocated buffer elements into the given slice
    /// starting at the given offset past the first allocated element, and return
    /// the amount read.
    #[must_use]
    pub fn read_allocated(&mut self, offset: usize, data: &mut [T]) -> usize
    where
        T: Copy,
    {
        let (size_1, offset, data) = {
            let slice = self.get_allocated(offset, data.len());
            data[..slice.len()].copy_from_slice(slice);
            (slice.len(), offset + slice.len(), &mut data[slice.len()..])
        };
        let size_2 = {
            let slice = self.get_allocated(offset, data.len());
            data[..slice.len()].copy_from_slice(slice);
            slice.len()
        };
        size_1 + size_2
    }

    /// Dequeue the given number of allocated buffer elements.
    ///
    /// # Panics
    /// Panics if the number of elements given exceeds the number of allocated elements.
    pub fn dequeue_allocated(&mut self, count: usize) {
        assert!(count <= self.len());
        self.length -= count;
        self.read_at = self.get_idx(count);
    }
}

impl<'a, T: 'a> From<ManagedSlice<'a, T>> for RingBuffer<'a, T> {
    fn from(slice: ManagedSlice<'a, T>) -> RingBuffer<'a, T> {
        RingBuffer::new(slice)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_buffer_length_changes() {
        let mut ring = RingBuffer::new(vec![0; 2]);
        assert!(ring.is_empty());
        assert!(!ring.is_full());
        assert_eq!(ring.len(), 0);
        assert_eq!(ring.capacity(), 2);
        assert_eq!(ring.window(), 2);

        ring.length = 1;
        assert!(!ring.is_empty());
        assert!(!ring.is_full());
        assert_eq!(ring.len(), 1);
        assert_eq!(ring.capacity(), 2);
        assert_eq!(ring.window(), 1);

        ring.length = 2;
        assert!(!ring.is_empty());
        assert!(ring.is_full());
        assert_eq!(ring.len(), 2);
        assert_eq!(ring.capacity(), 2);
        assert_eq!(ring.window(), 0);
    }

    #[test]
    fn test_buffer_enqueue_dequeue_one_with() {
        let mut ring = RingBuffer::new(vec![0; 5]);
        assert_eq!(
            ring.dequeue_one_with(|_| -> Result::<(), ()> { unreachable!() }),
            Err(Empty)
        );

        ring.enqueue_one_with(Ok::<_, ()>).unwrap().unwrap();
        assert!(!ring.is_empty());
        assert!(!ring.is_full());

        for i in 1..5 {
            ring.enqueue_one_with(|e| Ok::<_, ()>(*e = i))
                .unwrap()
                .unwrap();
            assert!(!ring.is_empty());
        }
        assert!(ring.is_full());
        assert_eq!(
            ring.enqueue_one_with(|_| -> Result::<(), ()> { unreachable!() }),
            Err(Full)
        );

        for i in 0..5 {
            assert_eq!(
                ring.dequeue_one_with(|e| Ok::<_, ()>(*e)).unwrap().unwrap(),
                i
            );
            assert!(!ring.is_full());
        }
        assert_eq!(
            ring.dequeue_one_with(|_| -> Result::<(), ()> { unreachable!() }),
            Err(Empty)
        );
        assert!(ring.is_empty());
    }

    #[test]
    fn test_buffer_enqueue_dequeue_one() {
        let mut ring = RingBuffer::new(vec![0; 5]);
        assert_eq!(ring.dequeue_one(), Err(Empty));

        ring.enqueue_one().unwrap();
        assert!(!ring.is_empty());
        assert!(!ring.is_full());

        for i in 1..5 {
            *ring.enqueue_one().unwrap() = i;
            assert!(!ring.is_empty());
        }
        assert!(ring.is_full());
        assert_eq!(ring.enqueue_one(), Err(Full));

        for i in 0..5 {
            assert_eq!(*ring.dequeue_one().unwrap(), i);
            assert!(!ring.is_full());
        }
        assert_eq!(ring.dequeue_one(), Err(Empty));
        assert!(ring.is_empty());
    }

    #[test]
    fn test_buffer_enqueue_many_with() {
        let mut ring = RingBuffer::new(vec![b'.'; 12]);

        assert_eq!(
            ring.enqueue_many_with(|buf| {
                assert_eq!(buf.len(), 12);
                buf[0..2].copy_from_slice(b"ab");
                (2, true)
            }),
            (2, true)
        );
        assert_eq!(ring.len(), 2);
        assert_eq!(&ring.storage[..], b"ab..........");

        ring.enqueue_many_with(|buf| {
            assert_eq!(buf.len(), 12 - 2);
            buf[0..4].copy_from_slice(b"cdXX");
            (2, ())
        });
        assert_eq!(ring.len(), 4);
        assert_eq!(&ring.storage[..], b"abcdXX......");

        ring.enqueue_many_with(|buf| {
            assert_eq!(buf.len(), 12 - 4);
            buf[0..4].copy_from_slice(b"efgh");
            (4, ())
        });
        assert_eq!(ring.len(), 8);
        assert_eq!(&ring.storage[..], b"abcdefgh....");

        for _ in 0..4 {
            *ring.dequeue_one().unwrap() = b'.';
        }
        assert_eq!(ring.len(), 4);
        assert_eq!(&ring.storage[..], b"....efgh....");

        ring.enqueue_many_with(|buf| {
            assert_eq!(buf.len(), 12 - 8);
            buf[0..4].copy_from_slice(b"ijkl");
            (4, ())
        });
        assert_eq!(ring.len(), 8);
        assert_eq!(&ring.storage[..], b"....efghijkl");

        ring.enqueue_many_with(|buf| {
            assert_eq!(buf.len(), 4);
            buf[0..4].copy_from_slice(b"abcd");
            (4, ())
        });
        assert_eq!(ring.len(), 12);
        assert_eq!(&ring.storage[..], b"abcdefghijkl");

        for _ in 0..4 {
            *ring.dequeue_one().unwrap() = b'.';
        }
        assert_eq!(ring.len(), 8);
        assert_eq!(&ring.storage[..], b"abcd....ijkl");
    }

    #[test]
    fn test_buffer_enqueue_many() {
        let mut ring = RingBuffer::new(vec![b'.'; 12]);

        ring.enqueue_many(8).copy_from_slice(b"abcdefgh");
        assert_eq!(ring.len(), 8);
        assert_eq!(&ring.storage[..], b"abcdefgh....");

        ring.enqueue_many(8).copy_from_slice(b"ijkl");
        assert_eq!(ring.len(), 12);
        assert_eq!(&ring.storage[..], b"abcdefghijkl");
    }

    #[test]
    fn test_buffer_enqueue_slice() {
        let mut ring = RingBuffer::new(vec![b'.'; 12]);

        assert_eq!(ring.enqueue_slice(b"abcdefgh"), 8);
        assert_eq!(ring.len(), 8);
        assert_eq!(&ring.storage[..], b"abcdefgh....");

        for _ in 0..4 {
            *ring.dequeue_one().unwrap() = b'.';
        }
        assert_eq!(ring.len(), 4);
        assert_eq!(&ring.storage[..], b"....efgh....");

        assert_eq!(ring.enqueue_slice(b"ijklabcd"), 8);
        assert_eq!(ring.len(), 12);
        assert_eq!(&ring.storage[..], b"abcdefghijkl");
    }

    #[test]
    fn test_buffer_dequeue_many_with() {
        let mut ring = RingBuffer::new(vec![b'.'; 12]);

        assert_eq!(ring.enqueue_slice(b"abcdefghijkl"), 12);

        assert_eq!(
            ring.dequeue_many_with(|buf| {
                assert_eq!(buf.len(), 12);
                assert_eq!(buf, b"abcdefghijkl");
                buf[..4].copy_from_slice(b"....");
                (4, true)
            }),
            (4, true)
        );
        assert_eq!(ring.len(), 8);
        assert_eq!(&ring.storage[..], b"....efghijkl");

        ring.dequeue_many_with(|buf| {
            assert_eq!(buf, b"efghijkl");
            buf[..4].copy_from_slice(b"....");
            (4, ())
        });
        assert_eq!(ring.len(), 4);
        assert_eq!(&ring.storage[..], b"........ijkl");

        assert_eq!(ring.enqueue_slice(b"abcd"), 4);
        assert_eq!(ring.len(), 8);

        ring.dequeue_many_with(|buf| {
            assert_eq!(buf, b"ijkl");
            buf[..4].copy_from_slice(b"....");
            (4, ())
        });
        ring.dequeue_many_with(|buf| {
            assert_eq!(buf, b"abcd");
            buf[..4].copy_from_slice(b"....");
            (4, ())
        });
        assert_eq!(ring.len(), 0);
        assert_eq!(&ring.storage[..], b"............");
    }

    #[test]
    fn test_buffer_dequeue_many() {
        let mut ring = RingBuffer::new(vec![b'.'; 12]);

        assert_eq!(ring.enqueue_slice(b"abcdefghijkl"), 12);

        {
            let buf = ring.dequeue_many(8);
            assert_eq!(buf, b"abcdefgh");
            buf.copy_from_slice(b"........");
        }
        assert_eq!(ring.len(), 4);
        assert_eq!(&ring.storage[..], b"........ijkl");

        {
            let buf = ring.dequeue_many(8);
            assert_eq!(buf, b"ijkl");
            buf.copy_from_slice(b"....");
        }
        assert_eq!(ring.len(), 0);
        assert_eq!(&ring.storage[..], b"............");
    }

    #[test]
    fn test_buffer_dequeue_slice() {
        let mut ring = RingBuffer::new(vec![b'.'; 12]);

        assert_eq!(ring.enqueue_slice(b"abcdefghijkl"), 12);

        {
            let mut buf = [0; 8];
            assert_eq!(ring.dequeue_slice(&mut buf[..]), 8);
            assert_eq!(&buf[..], b"abcdefgh");
            assert_eq!(ring.len(), 4);
        }

        assert_eq!(ring.enqueue_slice(b"abcd"), 4);

        {
            let mut buf = [0; 8];
            assert_eq!(ring.dequeue_slice(&mut buf[..]), 8);
            assert_eq!(&buf[..], b"ijklabcd");
            assert_eq!(ring.len(), 0);
        }
    }

    #[test]
    fn test_buffer_get_unallocated() {
        let mut ring = RingBuffer::new(vec![b'.'; 12]);

        assert_eq!(ring.get_unallocated(16, 4), b"");

        {
            let buf = ring.get_unallocated(0, 4);
            buf.copy_from_slice(b"abcd");
        }
        assert_eq!(&ring.storage[..], b"abcd........");

        let buf_enqueued = ring.enqueue_many(4);
        assert_eq!(buf_enqueued.len(), 4);
        assert_eq!(ring.len(), 4);

        {
            let buf = ring.get_unallocated(4, 8);
            buf.copy_from_slice(b"ijkl");
        }
        assert_eq!(&ring.storage[..], b"abcd....ijkl");

        ring.enqueue_many(8).copy_from_slice(b"EFGHIJKL");
        ring.dequeue_many(4).copy_from_slice(b"abcd");
        assert_eq!(ring.len(), 8);
        assert_eq!(&ring.storage[..], b"abcdEFGHIJKL");

        {
            let buf = ring.get_unallocated(0, 8);
            buf.copy_from_slice(b"ABCD");
        }
        assert_eq!(&ring.storage[..], b"ABCDEFGHIJKL");
    }

    #[test]
    fn test_buffer_write_unallocated() {
        let mut ring = RingBuffer::new(vec![b'.'; 12]);
        ring.enqueue_many(6).copy_from_slice(b"abcdef");
        ring.dequeue_many(6).copy_from_slice(b"ABCDEF");

        assert_eq!(ring.write_unallocated(0, b"ghi"), 3);
        assert_eq!(ring.get_unallocated(0, 3), b"ghi");

        assert_eq!(ring.write_unallocated(3, b"jklmno"), 6);
        assert_eq!(ring.get_unallocated(3, 3), b"jkl");

        assert_eq!(ring.write_unallocated(9, b"pqrstu"), 3);
        assert_eq!(ring.get_unallocated(9, 3), b"pqr");
    }

    #[test]
    fn test_buffer_get_allocated() {
        let mut ring = RingBuffer::new(vec![b'.'; 12]);

        assert_eq!(ring.get_allocated(16, 4), b"");
        assert_eq!(ring.get_allocated(0, 4), b"");

        let len_enqueued = ring.enqueue_slice(b"abcd");
        assert_eq!(ring.get_allocated(0, 8), b"abcd");
        assert_eq!(len_enqueued, 4);

        let len_enqueued = ring.enqueue_slice(b"efghijkl");
        ring.dequeue_many(4).copy_from_slice(b"....");
        assert_eq!(ring.get_allocated(4, 8), b"ijkl");
        assert_eq!(len_enqueued, 8);

        let len_enqueued = ring.enqueue_slice(b"abcd");
        assert_eq!(ring.get_allocated(4, 8), b"ijkl");
        assert_eq!(len_enqueued, 4);
    }

    #[test]
    fn test_buffer_read_allocated() {
        let mut ring = RingBuffer::new(vec![b'.'; 12]);
        ring.enqueue_many(12).copy_from_slice(b"abcdefghijkl");

        let mut data = [0; 6];
        assert_eq!(ring.read_allocated(0, &mut data[..]), 6);
        assert_eq!(&data[..], b"abcdef");

        ring.dequeue_many(6).copy_from_slice(b"ABCDEF");
        ring.enqueue_many(3).copy_from_slice(b"mno");

        let mut data = [0; 6];
        assert_eq!(ring.read_allocated(3, &mut data[..]), 6);
        assert_eq!(&data[..], b"jklmno");

        let mut data = [0; 6];
        assert_eq!(ring.read_allocated(6, &mut data[..]), 3);
        assert_eq!(&data[..], b"mno\x00\x00\x00");
    }

    #[test]
    fn test_buffer_with_no_capacity() {
        let mut no_capacity: RingBuffer<u8> = RingBuffer::new(vec![]);

        // Call all functions that calculate the remainder against rx_buffer.capacity()
        // with a backing storage with a length of 0.
        assert_eq!(no_capacity.get_unallocated(0, 0), &[]);
        assert_eq!(no_capacity.get_allocated(0, 0), &[]);
        no_capacity.dequeue_allocated(0);
        assert_eq!(no_capacity.enqueue_many(0), &[]);
        assert_eq!(no_capacity.enqueue_one(), Err(Full));
        assert_eq!(no_capacity.contiguous_window(), 0);
    }

    /// Use the buffer a bit. Then empty it and put in an item of
    /// maximum size. By detecting a length of 0, the implementation
    /// can reset the current buffer position.
    #[test]
    fn test_buffer_write_wholly() {
        let mut ring = RingBuffer::new(vec![b'.'; 8]);
        ring.enqueue_many(2).copy_from_slice(b"ab");
        ring.enqueue_many(2).copy_from_slice(b"cd");
        assert_eq!(ring.len(), 4);
        let buf_dequeued = ring.dequeue_many(4);
        assert_eq!(buf_dequeued, b"abcd");
        assert_eq!(ring.len(), 0);

        let large = ring.enqueue_many(8);
        assert_eq!(large.len(), 8);
    }
}
