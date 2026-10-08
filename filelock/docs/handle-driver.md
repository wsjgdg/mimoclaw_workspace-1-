# 驱动级句柄扫描 —— 设计说明与取舍

> 状态：**未实现**。本文档说明为什么没做、要做得付出什么代价，
> 以及如果一定要做，正确的架构是什么。

## 1. 现状：用户态句柄扫描能做到哪一步

`src/close_handle.c` 用的是用户态路线（与 Unlocker、Process Explorer 同款）：

```
NtQuerySystemInformation(SystemExtendedHandleInformation)   ← 枚举全系统句柄表
  → OpenProcess(PROCESS_DUP_HANDLE)                         ← 打开持有者进程
  → DuplicateHandle(复制到本进程)                            ← 拿到可查询的句柄
  → GetFinalPathNameByHandleW                               ← 比对路径
  → DuplicateHandle(DUPLICATE_CLOSE_SOURCE)                 ← 关闭源句柄（解锁）
```

需要管理员 + `SeDebugPrivilege`（代码里会自动尝试启用）。

### 已知盲区

| 盲区 | 原因 | 用户态能否补 |
|---|---|---|
| PPL 保护进程（csrss、部分杀软、Credential Guard） | `OpenProcess` 直接拒绝 | ❌ 必须驱动 |
| 内核句柄（`SystemExtendedHandleInformation` 不含） | 内核句柄不在进程句柄表里 | ❌ 必须驱动 |
| 枚举期间句柄表增长 | NtQSI 两次调用之间表会变 | ⚠️ 靠重试缓解 |
| 句柄被进程独占锁定后反复打开 | 行为层面 | ✅ 可重试 |

**本项目对盲区的处理是「如实告知」而不是「假装扫干净了」**：
`query_file_access()` 会记录 `OpenProcess` 失败的 PID，
诊断报告里会明确写出「有 N 个进程无法检查句柄（权限不足或受系统保护），
可能仍有隐藏占用」。这条已经实现。

## 2. 性能：为什么要做对象类型预过滤

全系统句柄表动辄几十万条，逐个 `DuplicateHandle` + `GetFinalPathNameByHandleW`
非常慢（秒级），而且每次复制都会短暂占用目标进程的句柄表锁。

`query_file_access()` 采用快速路径：

1. 先用本进程自己的一个文件句柄（打开 `NUL`）在表里反查出 **File 对象的
   `ObjectTypeIndex`**（该索引每次开机都变，必须运行时解析）；
2. 只对这个类型的句柄做 `DuplicateHandle` → 快一个数量级；
3. 若过滤后一条命中都没有，**自动退回全表扫描**，保证不漏报。

`close_file_handles()`（真正解锁的路径）暂未加此优化，保持已审阅的原逻辑不动。

## 3. 真·驱动级方案该怎么做

目标：在不 `OpenProcess` 的前提下，直接从内核拿到"哪个 EPROCESS 的哪个
FILE_OBJECT 指向目标路径"。

### 架构

```
用户态 UI  ←─ DeviceIoControl ─→  内核驱动
                                   │
                                   ├─ PsLookupProcessByProcessId 遍历 EPROCESS 链表
                                   ├─ ObReferenceObjectByHandle 不经过进程权限检查
                                   ├─ ObQueryNameString / SeLocateProcessImageName 比对路径
                                   └─ ZwDuplicateObject(内核态) 关闭句柄
```

关键点：

- **不要用 `ZwQuerySystemInformation` 做驱动版**——那是同一个接口，
  内核里调用并没有额外权限，收益为零；
- 收益来自 `ObReferenceObjectByHandle`：内核态拿 FILE_OBJECT 不走
  `OpenProcess` 的权限检查，因此能覆盖 PPL 进程；
- 关闭句柄用 `ZwDuplicateObject(..., DUPLICATE_CLOSE_SOURCE)`，
  同样绕过目标进程的句柄访问检查。

### 代价（这才是没做的真正原因）

1. **必须有 WDK + 签名**。Win10/11 x64 要求内核驱动有 EV 代码签名证书或
   测试签名模式（`bcdedit /set testsigning on`），普通用户根本装不上。
2. **蓝屏风险**。内核代码一旦写错（句柄表遍历竞争、IRQL 不对、对象引用泄漏）
   是整机崩溃，而不是程序报错。一个"查文件被谁占用"的小工具背这个责任不划算。
3. **杀软会标记**。内核驱动 + 强制关闭他人句柄的行为特征，
   会被绝大多数杀毒软件判定为 Rootkit/HackTool，分发即被拦截。
4. **维护成本**：每个 Windows 大版本的 EPROCESS / 句柄表结构都可能变，
   需要持续跟进（可以走 PDB 符号解析，但又依赖联网拉符号）。

### 结论

对本工具的定位（**给普通用户查"文件被谁占用"并给出对策**）来说，
驱动级是负收益：能多覆盖的场景很少（PPL 进程几乎不会持有普通文档），
代价是签名、蓝屏、杀软误报和长期维护。

因此采用的策略是：

- 用户态把能查的查干净（含类型预过滤提速）；
- 查不到的**如实列出来**，并告诉用户"这需要驱动级工具"；
- 真遇到 PPL 占用的极端场景，指向 Sysinternals 的
  [Process Explorer](https://learn.microsoft.com/sysinternals/downloads/process-explorer)
  （`Find → Find Handle or DLL`，它同样是用户态，但配合 `SeDebugPrivilege`
  能覆盖更多场景）或 WinObjEx64 这类专业工具。

## 4. 如果将来要做，落地清单

- [ ] WDK 环境 + EV 证书（或明确要求用户进测试签名模式）
- [ ] 驱动：`ObRegisterCallbacks` / 直接遍历 `PspCidTable`
- [ ] 用户态：`CreateFile(\\.\filelockDrv)` + `DeviceIoControl` 协议
- [ ] 安装：INF + `sc create` + 签名校验
- [ ] 蓝屏测试：Driver Verifier 全套跑通
- [ ] 杀软白名单申请
