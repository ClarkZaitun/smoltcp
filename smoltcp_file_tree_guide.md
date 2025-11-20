# Smoltcp 项目文件树说明文档

## 项目根目录

### 配置文件
- **Cargo.toml** - Rust项目的依赖和构建配置，定义了smoltcp库的版本、特性标志、依赖关系等
- **build.rs** - 构建脚本，用于编译时的代码生成或环境检查
- **.gitignore** - Git版本控制忽略文件配置
- **ci.sh** - 持续集成脚本，包含测试和构建的自动化流程

### 文档文件
- **README.md** - 项目介绍文档，包含smoltcp的基本功能、使用方法和特性说明
- **CHANGELOG.md** - 版本更新日志，记录每个版本的变更内容
- **LICENSE-0BSD.txt** - BSD 0-Clause开源许可证文件

### 项目配置
- **gen_config.py** - 配置生成脚本，用于生成项目配置相关代码

## 源代码目录 (src/)

### 核心库文件
- **lib.rs** - 主库入口文件，定义smoltcp的公共API和模块结构
- **lib.rs** - 包含分层架构说明：socket层、interface层、physical层、wire层
- **time.rs** - 时间相关功能，提供时间戳和超时管理
- **rand.rs** - 随机数生成器，用于协议栈中的随机数需求
- **tests.rs** - 单元测试集合
- **parsers.rs** - 协议解析器相关功能
- **macros.rs** - 宏定义文件，提供代码复用的宏工具

### 物理层 (src/phy/)
物理层负责与硬件设备交互，提供统一的设备抽象接口。

- **mod.rs** - 物理层主模块，定义Device trait和核心数据结构
  - Device trait: 网络设备抽象接口
  - PacketMeta: 数据包元数据
  - DeviceCapabilities: 设备能力描述
  - Checksum: 校验和行为配置
  
- **loopback.rs** - 回环设备实现，用于本地测试
- **tracer.rs** - 数据包跟踪器，用于调试和监控
- **fault_injector.rs** - 故障注入器，用于测试网络错误处理
- **fuzz_injector.rs** - 模糊测试注入器，用于安全性测试
- **pcap_writer.rs** - PCAP文件写入器，用于数据包捕获
- **raw_socket.rs** - 原始套接字设备实现
- **tuntap_interface.rs** - TUN/TAP虚拟网络接口实现
- **sys/** - 系统相关实现目录

### 接口层 (src/iface/)
接口层处理网络接口逻辑，包括路由、邻居缓存、分片重组等。

- **mod.rs** - 接口层主模块，导出公共接口
- **interface/** - 网络接口核心实现
  - 包含Interface结构体，负责帧接收/发送和状态管理
  - 处理不同介质类型（Ethernet、IEEE 802.15.4）
  - 支持IPv4/IPv6协议栈
  
- **fragmentation.rs** - IP分片重组处理
- **neighbor.rs** - 邻居缓存管理（ARP和NDP）
- **route.rs** - 路由表管理
- **socket_set.rs** - 套接字集合管理
- **socket_meta.rs** - 套接字元数据
- **packet.rs** - 数据包处理相关功能
- **rpl/** - RPL（IPv6路由协议）实现

### 套接字层 (src/socket/)
套接字层提供各种网络协议的套接字实现。

- **mod.rs** - 套接字层主模块
- **tcp.rs** - TCP协议套接字实现
- **tcp/** - TCP协议相关辅助功能
- **udp.rs** - UDP协议套接字实现
- **icmp.rs** - ICMP协议套接字实现
- **raw.rs** - 原始套接字实现
- **dhcpv4.rs** - DHCPv4客户端实现
- **dns.rs** - DNS客户端实现
- **waker.rs** - 异步唤醒机制

### 存储层 (src/storage/)
存储层提供数据缓冲区管理功能。

- **mod.rs** - 存储层主模块
- **packet_buffer.rs** - 数据包缓冲区管理
- **ring_buffer.rs** - 环形缓冲区实现
- **assembler.rs** - TCP数据重组器

### 协议层 (src/wire/)
协议层负责数据包的低级别解析和构建。

- **mod.rs** - 协议层主模块，定义Packet和Repr结构体族
- **ethernet.rs** - 以太网协议实现
- **arp.rs** - ARP协议实现
- **ipv4.rs** - IPv4协议实现
- **ipv6.rs** - IPv6协议实现
- **ipv6fragment.rs** - IPv6分片扩展头
- **icmpv4.rs** - ICMPv4协议实现
- **icmpv6.rs** - ICMPv6协议实现
- **tcp.rs** - TCP协议实现
- **udp.rs** - UDP协议实现
- **dhcpv4.rs** - DHCPv4协议实现
- **dns.rs** - DNS协议实现
- **ieee802154.rs** - IEEE 802.15.4协议实现
- **sixlowpan/** - 6LoWPAN协议实现
- **ndisc.rs** - 邻居发现协议
- **pretty_print.rs** - 协议数据包美化打印

## 示例目录 (examples/)

包含各种使用场景的示例代码：

- **client.rs** - TCP客户端示例
- **server.rs** - TCP服务器示例
- **ping.rs** - ICMP ping示例
- **dhcp_client.rs** - DHCP客户端示例
- **dns.rs** - DNS查询示例
- **httpclient.rs** - HTTP客户端示例
- **loopback.rs** - 回环测试示例
- **benchmark.rs** - 性能基准测试
- **multicast.rs** - IPv4组播示例
- **multicast6.rs** - IPv6组播示例
- **sixlowpan.rs** - 6LoWPAN示例
- **tcpdump.rs** - 数据包捕获示例
- **utils.rs** - 示例工具函数

## 测试目录 (tests/)

- **netsim.rs** - 网络仿真测试
- **snapshots/** - 测试快照数据

## 工具目录 (utils/)

- **packet2pcap.rs** - 数据包转PCAP格式工具

## 模糊测试目录 (fuzz/)

- **Cargo.toml** - 模糊测试项目配置
- **fuzz_targets/** - 模糊测试目标
  - **packet_parser.rs** - 数据包解析器测试
  - **tcp_headers.rs** - TCP头部测试
  - **dhcp_header.rs** - DHCP头部测试
  - **ieee802154_header.rs** - IEEE 802.15.4头部测试
  - **sixlowpan_packet.rs** - 6LoWPAN数据包测试

## 基准测试目录 (benches/)

- **bench.rs** - 性能基准测试代码

## GitHub工作流 (.github/)

- **workflows/** - GitHub Actions工作流配置
  - **test.yml** - 自动化测试流程
  - **coverage.yml** - 代码覆盖率测试
  - **rustfmt.yaml** - 代码格式化检查
  - **fuzz.yml** - 模糊测试流程
  - **matrix-bot.yml** - 矩阵通知机器人
- **codecov.yml** - Codecov覆盖率配置

## 文件依赖关系

```
应用层 (examples/)
    ↓
套接字层 (src/socket/)
    ↓
接口层 (src/iface/)
    ↓
协议层 (src/wire/)
    ↓
物理层 (src/phy/)
    ↓
硬件设备
```

## 核心数据结构

- **Device trait**: 物理层设备抽象
- **Interface**: 网络接口管理
- **Socket**: 各种协议套接字
- **Packet/Repr**: 协议数据包表示
- **RingBuffer**: 环形缓冲区
- **PacketBuffer**: 数据包缓冲区

这个文件树结构体现了smoltcp的分层设计理念，每一层都有明确的职责和接口定义，便于维护和扩展。