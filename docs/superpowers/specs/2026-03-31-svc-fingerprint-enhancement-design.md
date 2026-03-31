# SVC 级指纹采集增强设计

> 参考 sgmain VM 的 SVC 指纹采集方案，增强 Launch 指纹模块的运行时验证能力和跨安装设备追踪能力。

## 1. 背景

当前指纹模块已有 37 个指纹项，覆盖 Java/Native/Syscall 三层。但与 sgmain 级方案对比，缺少：
- CPU 频率等硬件运行时指纹
- 系统属性 mmap 直读（第四层）
- 运行时完整性指标（RWX检测、urandom校验）
- 跨安装持久化设备追踪（图片 LSB 隐写）

## 2. 设计总览

新增内容分三类：

```
┌─────────────────────────────────────────────────────────────┐
│  第一类：新增设备指纹项（稳定、可比对、纳入 Hash）            │
│  ├── #38 CPU 频率指纹（大小核频率模式）                      │
│  ├── #39 /etc/hosts Hash                                    │
│  ├── #40 SELinux 状态                                       │
│  └── #41 进程包名验证（/proc/self/cmdline）                  │
├─────────────────────────────────────────────────────────────┤
│  第二类：运行时完整性指标（信任分扣分因子，不进指纹列表）     │
│  ├── RWX 匿名内存区域检测                                    │
│  ├── /dev/urandom 完整性校验                                 │
│  └── 系统属性 mmap vs Native 一致性比对                      │
├─────────────────────────────────────────────────────────────┤
│  第三类：持久化引擎（跨安装设备追踪）                         │
│  ├── PersistentFingerprint.java — 持久化管理                 │
│  ├── LSB 隐写编解码 — PNG 像素嵌入指纹                       │
│  └── device_token — UUID + 硬件 Hash 持久化                  │
└─────────────────────────────────────────────────────────────┘
```

## 3. 第一类：新增设备指纹项

### 3.1 CPU 频率指纹 (#38)

**采集路径：**
```
/sys/devices/system/cpu/cpu{0-N}/cpufreq/cpuinfo_max_freq
```

**输出格式：** `"1800000,1800000,1800000,1800000,2400000,2400000,2800000,2800000"`

**三层实现：**
| 层 | 方法 |
|---|---|
| Java | ReflectionUtils.readFileFirstLine() 逐核读取 |
| Native | fopen/fgets 逐核读取，native-lib.cpp |
| Syscall | syscall_read_file() 逐核读取，native-lib.cpp |

**容错：** 核心不存在时跳过（不同设备 4/6/8 核），读取失败的核不纳入字符串。

**风控价值：**
- 模拟器所有核频率相同，真机有大小核差异
- 改机工具很少伪造 cpufreq
- 不同 SoC 的频率模式唯一，可作为硬件指纹

### 3.2 /etc/hosts Hash (#39)

**采集路径：** `/etc/hosts`，fallback `/system/etc/hosts`

**输出格式：** djb2 hash，如 `"a3f8c2d1"`

**三层实现：**
| 层 | 方法 |
|---|---|
| Java | ReflectionUtils.readFile() → djb2 hash |
| Native | read_file_native() → djb2 hash (native-lib.cpp) |
| Syscall | syscall_read_file() → djb2 hash (native-lib.cpp) |

**风控价值：**
- 正常设备 hosts 只有 `127.0.0.1 localhost`
- Magisk 模块、广告屏蔽、DNS 劫持会修改 hosts
- Hash 变化 = 环境被篡改

### 3.3 SELinux 状态 (#40)

**采集路径：**
- `/sys/fs/selinux/enforce` → `"1"` (Enforcing) 或 `"0"` (Permissive)
- `/proc/self/attr/current` → SELinux context，**只取域部分**

**输出格式：** `"Enforcing|u:r:untrusted_app"`

**注意：** `/proc/self/attr/current` 返回完整 context 如 `u:r:untrusted_app:s0:c512,c768`，末尾 category (`c512,c768`) 在不同进程实例间会变化。必须截断到第三个冒号前：`u:r:untrusted_app`。

**三层实现：**
| 层 | 方法 |
|---|---|
| Java | readFileFirstLine() 两个文件 + 截断拼接 |
| Native | read_file_native() + 截断拼接 |
| Syscall | syscall_read_file() + 截断拼接 |

**风控价值：**
- Permissive = root/自定义 ROM
- 异常 context (如 `u:r:magisk:s0`) = Magisk 注入

### 3.4 进程包名验证 (#41)

**采集路径：** `/proc/self/cmdline`

**输出格式：** `"com.xff.launch"`

**注意：** cmdline 内容以 `\0` 结尾，读取后需清理 null 字符。

**三层实现：**
| 层 | 方法 |
|---|---|
| Java | context.getPackageName() — 可被 Hook |
| Native | fopen("/proc/self/cmdline") — 可被 PLT Hook |
| Syscall | syscall_read_file("/proc/self/cmdline") — 最可信 |

**风控价值：**
- VirtualApp/多开 → cmdline 是宿主包名，Java 返回客户包名 → 不一致
- 重打包 → 包名被改但 cmdline 可能暴露差异

## 4. 第二类：运行时完整性指标

这些不是 FingerprintItem，不进指纹列表。它们作为独立检查，结果影响信任分。

### 4.1 RWX 匿名内存区域检测

**做法：** 调用已有 `NativeDetector.countAnonymousRwxMemory()`

**扣分规则：**
| RWX 区域数 | 信任分影响 |
|---|---|
| 0 | 不扣分 |
| 1-2 | 扣 10 分 |
| 3+ | 扣 25 分 |

### 4.2 /dev/urandom 完整性校验

**做法：** 三层各读 /dev/urandom 16 字节：
- Java: `new FileInputStream("/dev/urandom")`
- Native: `fopen("/dev/urandom", "r") + fread()`
- Syscall: `syscall_open + syscall_read`

**检测逻辑：**
- 读取结果全零 → 被 Hook（扣 20 分）
- 三次读取结果完全相同 → 被 Hook 返回固定值（扣 20 分）
- 正常情况三次结果都不同（随机数本身每次不同不做一致性比对）

### 4.3 系统属性 mmap vs Native 一致性

**做法：** 对 5 个关键属性做 mmap 直读，与 `__system_property_get()` 结果比对：
- `ro.serialno`
- `ro.product.model`
- `ro.product.brand`
- `ro.build.fingerprint`
- `ro.product.device`

**mmap 实现 (native-lib.cpp)：**
```c
// 通过 /dev/__properties__/u:object_r:XXX_prop:s0 直接 mmap
// Android 9+ 使用 property_info 格式
// 1. 打开 /dev/__properties__/properties_serial
// 2. mmap 映射属性区域
// 3. 遍历 trie 结构查找属性值
// 4. 直接读取内存中的值，不经过 __system_property_get
```

**扣分规则：** 任一属性 mmap 值 ≠ Native 值 → 扣 20 分（意味着 `__system_property_get` 被 Hook）

## 5. 第三类：持久化引擎

### 5.1 整体流程

```
首次安装:
  1. 采集所有指纹 → 生成 hardwareHash
  2. 生成 UUID device_token
  3. 组装 payload = token + hardwareHash + timestamp
  4. 创建 64×64 PNG 图片，payload 编码进 LSB
  5. 写入 /sdcard/.launch_fp/.fp_0.png (MANAGE_EXTERNAL_STORAGE)

重新安装:
  1. 检查 /sdcard/.launch_fp/.fp_0.png 是否存在
  2. 存在 → 读取图片，LSB 解码提取 payload
  3. 解析出 old_token + old_hardwareHash + old_timestamp
  4. 采集当前指纹 → 生成当前 hardwareHash
  5. 比对: old_hardwareHash == 当前 hardwareHash?
     - 一致 → 同一设备，未改机，恢复 old_token
     - 不一致 → 设备指纹变化，疑似改机/刷机
  6. 不存在 → 全新设备或存储被清理，生成新 token
```

### 5.2 LSB 隐写编解码

**图片规格：**
- 格式：PNG（无损压缩，不破坏 LSB）
- 尺寸：64×64 像素
- 容量：64 × 64 × 3 bit (RGB 各 1 bit) = 1536 字节
- 实际数据：UUID(36) + SHA256(64) + timestamp(13) + 分隔符 = ~120 字节

**编码算法：**
```
输入: byte[] payload
1. 创建 64×64 ARGB Bitmap
2. 用随机像素值填充（看起来像噪声图片）
3. 前 4 字节写入 payload 长度 (big-endian)
4. 后续字节逐 bit 写入每个像素的 R/G/B 最低位
5. 保存为 PNG
```

**解码算法：**
```
输入: Bitmap image
1. 读取前 4×8=32 个像素的 LSB → 得到 payload 长度
2. 按长度继续读取后续像素的 LSB
3. 每 8 bit 组装为 1 byte
4. 返回 byte[] payload
```

### 5.3 存储路径与权限

**权限：** `MANAGE_EXTERNAL_STORAGE` (AndroidManifest.xml)
```xml
<uses-permission android:name="android.permission.MANAGE_EXTERNAL_STORAGE" />
```

**兼容：** `android:requestLegacyExternalStorage="true"` (Android 9-10)

**目录结构：**
```
/sdcard/.launch_fp/
├── .nomedia          ← 阻止媒体扫描
└── .fp_0.png         ← 隐写图片
```

### 5.4 PersistentFingerprint.java

```java
public class PersistentFingerprint {
    // 存储路径
    private static final String DIR = ".launch_fp";
    private static final String FILE = ".fp_0.png";

    // 公共方法
    public static void save(Context ctx, String token, String hwHash);
    public static PersistentData load(Context ctx);  // 返回 null 如果不存在
    public static boolean exists(Context ctx);

    // LSB 编解码（内部方法）
    private static Bitmap encode(byte[] payload);
    private static byte[] decode(Bitmap image);

    // 数据结构
    public static class PersistentData {
        public String token;           // UUID
        public String hardwareHash;    // SHA256
        public long timestamp;         // 首次写入时间
        public boolean deviceChanged;  // 与当前 hwHash 比对结果
    }
}
```

## 6. 文件改动清单

| 文件 | 改动类型 | 内容 |
|------|---------|------|
| `native-lib.cpp` | 修改 | 新增 8 个 JNI 方法：CPU频率(2)、hosts hash(2)、SELinux(2)、cmdline(2)；新增 mmap 属性读取(1)、urandom 校验(2) |
| `NativeDetector.java` | 修改 | 新增对应 native 方法声明 |
| `FingerprintFragment.java` | 修改 | 新增 4 个指纹项采集 + 运行时完整性指标检查 + 持久化读写调用 + 信任分计算更新 |
| `FingerprintResult.java` | 修改 | 信任分计算加入运行时指标扣分 |
| `PersistentFingerprint.java` | **新建** | 持久化引擎 + LSB 隐写 |
| `ReflectionUtils.java` | 修改 | 新增 djb2Hash() 方法 |
| `AndroidManifest.xml` | 修改 | 新增 MANAGE_EXTERNAL_STORAGE 权限 + requestLegacyExternalStorage |
| `strings.xml` | 修改 | 新增指纹项显示名称 |

## 7. 信任分计算更新

```
原公式: trustLevel = max(0, 100 - inconsistentCount × 15)

新公式: trustLevel = max(0, 100 
    - inconsistentCount × 15           ← 原有：指纹项不一致扣分
    - rwxPenalty                        ← 新增：RWX 区域扣分 (0/10/25)
    - urandomPenalty                    ← 新增：urandom 异常扣分 (0/20)
    - mmapPenalty                       ← 新增：属性 mmap 不一致扣分 (0/20)
    - persistentPenalty                 ← 新增：持久化指纹变化扣分 (0/15)
)
```
