# ethmirror

使用 Go 开发的 Linux 入站流量镜像程序，以 **Linux 4.19** 为最低兼容目标。默认将 eth0 收到的以太网帧复制到 eth1，同时保留原包的本机接收路径。

```text
eth0 ingress → XDP_PASS → TC ingress
                            ├── bpf_clone_redirect(ifindex, 0) → eth1 egress
                            └── TC_ACT_UNSPEC → 后续 TC 规则 / 本机接收路径
```

XDP 负责计数和放行，实际复制由 TC 的 `bpf_clone_redirect` 完成。单次 XDP 处理无法同时返回 `XDP_REDIRECT` 和 `XDP_PASS`，因此此功能使用 skb/TC 镜像路径，不提供纯重定向模式。

## 构建

需要 Go 1.23 或更新版本（`kardianos/service` 的最低 Go 版本）。在 Linux 项目根目录执行：

```bash
go build -o ethmirror ./cmd/ethmirror
```

整个工程都是 Go。使用 `cilium/ebpf/asm` 直接构造少量 eBPF 指令，用户态用 `cilium/ebpf` 加载、`vishvananda/netlink` 挂载。**无需 Rust、nightly、Clang、LLVM、C 编译器、内核头文件、go generate 或 Shell 构建脚本。** 运行时不读取 ELF 文件，只需部署一个可执行文件。

在其他系统仅交叉构建 Linux 用户态程序：

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o bin/ethmirror-linux-amd64 ./cmd/ethmirror
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o bin/ethmirror-linux-arm64 ./cmd/ethmirror
```

使用当前环境的 Go，不主动安装或切换工具链；依赖版本固定在 `go.mod` / `go.sum`。

## 目录结构

```text
.
├── cmd/ethmirror/              # 可执行程序入口
│   ├── main.go                # 信号处理、启动及错误输出
│   ├── options.go             # 命令行参数与校验
│   ├── service.go             # 服务管理子命令
│   └── service_test.go        # 服务命令参数检查
├── internal/daemon/           # kardianos/service 适配与生命周期测试
├── internal/mirror/           # 项目内部的流量镜像实现
│   ├── options.go             # 镜像配置
│   ├── run_linux.go           # 内核检查、加载、统计和运行生命周期
│   ├── run_other.go           # 非 Linux 平台提示
│   ├── attach_linux.go        # XDP / TC 挂载和卸载
│   ├── program.go             # eBPF 指令、map 和统计结构
│   └── program_test.go        # 字节码和 map 布局检查
├── tests/integration.py       # 目标 Linux 上的收发验收
├── go.mod
├── go.sum
└── README.md
```

`cmd` 负责命令行入口，`internal` 代码仅供本项目使用。单元测试与实现放在同一包目录，跨进程和网络验收放在 `tests`。

## Linux 4.19 兼容方式

- 最低内核为 Linux 4.19，启动时检查内核版本。
- XDP 使用旧版 Netlink 接口，TC 使用 clsact ingress，**不依赖 BPF link、TCX**。
- 只用经典 eBPF 指令和已有 helper，不使用 JMP32、有界循环、新原子指令、BPF 子程序调用、全局数据 map、BTF 或 CO-RE。
- 配置使用普通 ARRAY，统计使用 PERCPU_ARRAY，均不要求内核 BTF 或 `/sys/kernel/btf/vmlinux`。
- 初始化时处理旧内核的 `RLIMIT_MEMLOCK` 限制。

目标内核需要开启 `CONFIG_BPF`、`CONFIG_BPF_SYSCALL`、`CONFIG_NET_CLS_BPF`、`CONFIG_NET_CLS_ACT`、`CONFIG_NET_SCH_INGRESS`，以及正常的网络与 Netlink 支持；建议启用架构支持的 BPF JIT。运行需要 root 或等效权限，4.19 上包括 BPF 加载所需的 `CAP_SYS_ADMIN` 和网络管理权限。native 模式取决于网卡驱动，支持不足时显式使用 skb 模式。

当前仅完成源码与字节码静态检查、Linux 目标交叉编译；**尚未在真实 Linux 4.19 内核上完成加载与收发实测**。发行版内核配置、回移补丁、网卡驱动和 MTU 仍需在目标设备验收。

## 运行

先根据实际部署配置接口。以下示例会修改网卡状态，镜像接收口通常需要混杂模式：

```bash
sudo ip link set eth0 up
sudo ip link set eth0 promisc on
sudo ip link set eth1 up

sudo ./ethmirror --ingress eth0 --egress eth1
# generic/SKB XDP：
sudo ./ethmirror --ingress eth0 --egress eth1 --xdp-mode skb
```

选项：

| 参数 | 默认值 | 含义 |
| --- | --- | --- |
| `--ingress` | `eth0` | 接收镜像报文的接口 |
| `--egress` | `eth1` | 发出副本的接口 |
| `--xdp-mode` | `native` | `native` 或 `skb`，不静默降级 |
| `--stats-interval` | `5` | 累计统计输出间隔，单位秒 |
| `--tc-priority` | `100` | TC ingress 优先级，1..65535 |
| `--tc-handle` | `1` | TC filter handle，1..4294967295 |

程序不自动修改 UP、混杂模式、MTU、offload 或 IP 配置。只镜像 eth0 的入站流量，不镜像本机从 eth0 发出的包。不修改 MAC、IP、TTL、VLAN，不执行路由或 ARP 解析，也不需要 `ip_forward`。eth1 的副本仍使用原目的 MAC，对端需要能接收相应帧。

## 服务管理

通过 [github.com/kardianos/service](https://pkg.go.dev/github.com/kardianos/service) 实现，自动使用 Linux 上可用的服务后端；systemd 下服务名为 `ethmirror.service`。现有的 `ethmirror --ingress ...` 命令仍以前台方式运行。

先把可执行文件放到固定位置，再安装服务。例如：

```bash
sudo install -m 0755 ./ethmirror /usr/local/bin/ethmirror
sudo /usr/local/bin/ethmirror service install --ingress eth0 --egress eth1 --xdp-mode skb
sudo /usr/local/bin/ethmirror service start
sudo /usr/local/bin/ethmirror service status
sudo /usr/local/bin/ethmirror service stop
sudo /usr/local/bin/ethmirror service restart
sudo /usr/local/bin/ethmirror service uninstall
```

也支持省略 `service` 前缀，例如 `ethmirror install ...`、`ethmirror start`、`ethmirror status`。

| 命令 | 行为 |
| --- | --- |
| `install [镜像参数]` | 注册服务并保存参数；systemd 下同时启用开机启动，不立即启动 |
| `start` | 按安装时保存的参数启动 |
| `stop` | 发送停止请求，等待 XDP / TC 卸载完成 |
| `restart` | 停止后按已保存的参数重新启动 |
| `status` | 显示 running、stopped、not installed，或报告查询/服务故障 |
| `uninstall` | 先停止运行中的服务，再取消注册；不删除可执行文件 |

`install` 引用当前可执行文件的绝对路径，不复制程序，因此安装后不要移动或删除该文件。网卡、XDP 模式、统计间隔及 TC priority/handle 都会写入服务配置；`start` / `restart` 不接受修改参数，需修改配置时先卸载，再用新参数安装。

systemd 下配置位于 `/etc/systemd/system/ethmirror.service`，日志可用 `journalctl -u ethmirror -f` 查看。服务以 root 运行，在网络就绪之后启动，但仍需提前配置接口的 UP、混杂模式、MTU 等。镜像程序后台出错时服务会以错误退出，systemd 使用 `on-failure` 策略重新启动；重试间隔由库生成的服务配置决定。卸载不会删除保留的 clsact qdisc。

服务生命周期由库的 `Start` / `Stop` 回调和 `RunWait` 协调：启动不阻塞服务管理器，停止等待镜像程序清理；后台加载或运行失败会结束服务进程。`service run` 是安装配置使用的内部启动入口，日常管理使用上述六个命令。

原包仍遵循后续 TC、协议栈与防火墙规则。对于原目的地址不是本机的 SPAN 流量，保留本机收包路径允许混杂模式抓包，并不自动让本机 TCP/UDP socket 接收发往其他主机的包。已有的前置 TC 过滤器可能在镜像程序之前消费报文。

XDP 添加使用 `UPDATE_IF_NOEXIST`，TC filter 使用独占添加，重复启动不会替换已有程序。退出时先核对程序 ID，再卸载自己的挂载，保留 clsact qdisc。Linux 4.19 不具备较新内核的原子 XDP 条件卸载能力，运行和退出期间应避免其他程序并发修改同一接口的挂载。

Ctrl+C / SIGTERM 触发清理，启动中途失败也会清理已建立的挂载。传统 Netlink 挂载不会因进程被 SIGKILL 或崩溃而自动卸载，必要时先确认归属，再手动清理：

```bash
sudo ip -details link show eth0
sudo tc filter show dev eth0 ingress
# 确认是本程序后，按实际模式和参数清理：
sudo ip link set dev eth0 xdpdrv off
# skb 模式改用：sudo ip link set dev eth0 xdpgeneric off
sudo tc filter del dev eth0 ingress pref 100 handle 1 bpf
```

## 统计与报文保真

输出字段：`xdp_packets`、`xdp_bytes`、`tc_packets`、`clone_ok`、`clone_errors`、`unconfigured`。统计使用 per-CPU map 后汇总；`clone_ok` 表示 helper 返回成功，不保证物理链路送达。镜像失败时原包仍继续接收。正常配置下 `unconfigured` 应为 0。

GRO/LRO、VLAN offload、发送分段和 MTU 可能影响逐帧形式。需要逐帧保真时按网卡能力关闭有关 offload（例如 `ethtool -K eth0 gro off lro off rxvlan off`），并在 eth1 对端抓包验收。硬件剥离的前导码、FCS 不在复制范围内。避免把 eth1 输出重新镜像回 eth0，防止流量循环。

## 检查与验收

只检查源码和字节码，不加载内核、不修改网络：

```bash
go test ./...
GOOS=linux GOARCH=amd64 go vet ./...
```

字节码测试检查指令可编码、跳转可解析、无后向跳转与 JMP32、helper 白名单、放行返回值及统计 map 布局。这不能替代目标内核 verifier 和收发验收。

在目标 Linux 4.19 上构建后，由部署方运行（需要 Python 3、iproute2、root）：

```bash
sudo python3 tests/integration.py
sudo python3 tests/integration.py --xdp-mode native
```

验收脚本创建三个隔离网络命名空间和两对 veth，默认使用 skb 模式，退出时清理。检查本机 UDP 收包、eth1 恰好一份逐字节一致的 UDP/二层/VLAN 副本、重复启动、出口消失后原包接收，以及 SIGTERM 清理。4.19 的 veth native XDP 能力可能因版本和驱动限制不足，native 模式还应在实际物理网卡测试。

参考：[Linux 4.19 clone_redirect 实现](https://github.com/torvalds/linux/blob/v4.19/net/core/filter.c)、[Linux 4.19 BPF 接口](https://github.com/torvalds/linux/blob/v4.19/include/uapi/linux/bpf.h)、[cilium/ebpf](https://github.com/cilium/ebpf)、[Netlink](https://github.com/vishvananda/netlink)。
