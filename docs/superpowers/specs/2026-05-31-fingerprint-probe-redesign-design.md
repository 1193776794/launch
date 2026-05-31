# 指纹板块细粒度重构设计（探针模型 + 声明式注册表）

> 目标：把指纹采集从"3 层压扁单值"升级为"多路探针逐条留存"，每项可展开看各采集方式结果；**架构声明式、可快捷扩展、易读**。

## 1. 背景与痛点

现状 `FingerprintFragment.performCollection()` 约 700 行过程式代码，每个指纹项内部尝试多种取证手段（反射 / Settings API / `__system_property_get` / 读 `/proc`·`/sys` / mmap），但最后用 `nonEmpty(...)` **合并成 `JAVA/NATIVE/SYSCALL` 三层单值**，中间各路结果被丢弃，UI 无法呈现。同时存在信任分/扣分体系，用户决定**取消信任分**，改为每项"一致/不一致"颜色标识。

## 2. 设计目标（按优先级）

1. **可扩展**：加一个新指纹 = 在一个文件里加一个 `define(...)` 块（5 行）；加一种新采集方式 = 枚举加一行。引擎/UI/投票/Hash 自动接住。
2. **易读**：Fragment 不再含取证逻辑，只负责 调引擎 → 拿结果 → 喂 Adapter。
3. **可视化**：折叠卡（颜色标识一致性）→ 展开看每条采集方式的"方式·手段·来源·结果·状态"。
4. **取消信任分**：删除 `trustLevel` 与全部 penalty 逻辑。

## 3. 架构分层

```
声明层  FingerprintDefinitions   ← 所有指纹声明聚集地（加指纹只动这里）
执行层  FingerprintEngine        ← 跑每条 probe → 建 probe → 投票 → 出 hash
模型层  ProbeMethod / ProbeStatus / CollectProbe / Collector
        FingerprintItem / FingerprintResult / FingerprintSpec
UI 层   FingerprintItemAdapter + item_fingerprint.xml / item_probe.xml
        FingerprintFragment（瘦身）+ fragment_fingerprint.xml
```

## 4. 模型层

### 4.1 ProbeMethod（采集方式枚举）

| 枚举 | 显示名 | 图标(emoji) | 抗 Hook 层 | 颜色组 |
|---|---|---|---|---|
| `JAVA_REFLECT` | Java 反射 | 🔍 | 高·易Hook | tier_high |
| `JAVA_API` | Java API | ☕ | 高·易Hook | tier_high |
| `NATIVE_PROP` | 属性(native) | ⚙ | 中 | tier_mid |
| `NATIVE_FILE` | JNI 文件 | 🔧 | 中 | tier_mid |
| `SYSCALL` | 系统调用 | 🛡 | 底·难Hook | tier_low |
| `MMAP` | 内存 mmap | 🧠 | 底·难Hook | tier_low |

字段：`displayName`、`icon`、`tier`(枚举 HIGH/MID/LOW，用于图标着色)。

### 4.2 ProbeStatus

`OK`（有效值）/ `EMPTY`（空或 N/A）/ `ERROR`（采集抛异常）/ `NA`（该项不适用此方式，理论上不出现——不适用就不声明该 probe）。

### 4.3 Collector（函数式接口）

```java
@FunctionalInterface
public interface Collector { String collect() throws Exception; }
```

### 4.4 CollectProbe

字段：`ProbeMethod method`、`String api`（具体手段，如 `Build.getSerial()`）、`String source`（来源路径，可空）、`String value`、`ProbeStatus status`、`boolean outlier`（投票离群标红）。

### 4.5 FingerprintItem（重写）

- 字段：`id`、`displayName`、`List<CollectProbe> probes`。
- `isConsistent()`：对所有 `status==OK` 且非空的 probe，规整化（trim）后两两比较；全等→true；只有 0/1 个有效值→true（无从判定）。
- `getHitValue()`：OK 探针的多数值（众数）；无 OK → `"N/A"`。
- 投票时把与众数不同的 OK 探针 `outlier=true`。
- 移除旧 `Map<DetectionLayer,String>` API。

### 4.6 FingerprintResult（瘦身）

- 保留：`items`、`compositeFingerprint`、`hardwareHash`、`softwareHash`、`collectTime`、`getConsistentCount/getInconsistentCount`。
- 删除：`trustLevel`、`rwx/urandom/mmap/persistentPenalty`、`calculateTrustLevel()`、`tamperingDetected`（改为派生 `hasInconsistency()=inconsistentCount>0`）。
- `compositeFingerprint`/hash 由引擎按 spec 的 `hash` 标签拼装。

### 4.7 FingerprintSpec + builder

```java
FingerprintSpec.define(id, displayName, Group group, HashTag hash)
    .probe(ProbeMethod method, String api, Collector collector)
    .probe(ProbeMethod method, String api, String source, Collector collector)
```

- `Group`：IDENTITY / KERNEL / HARDWARE / BOOT / SYSTEM / RUNTIME（用于分组展示，可选）。
- `HashTag`：HARDWARE / SOFTWARE / NONE（引擎据此自动归集 hash）。

## 5. 声明层 FingerprintDefinitions

一个静态方法 `List<FingerprintSpec> build(Context ctx, NativeDetector nd)` 返回全部 ~30 项声明。每项把现有 `performCollection()` 里的取证调用**原样搬进 lambda**，按方式逐条 `.probe(...)`。示例：

```java
define("serial", "设备序列号", Group.IDENTITY, HashTag.HARDWARE)
    .probe(JAVA_REFLECT, "Build.getSerial()",       () -> ReflectionUtils.getSerial())
    .probe(JAVA_API,     "Build.SERIAL",            () -> Build.SERIAL)
    .probe(NATIVE_PROP,  "ro.serialno",             () -> nd.getBuildPropertyNative("ro.serialno"))
    .probe(SYSCALL, "openat /sys/.../iSerial", "/sys/class/android_usb/android0/iSerial",
                                                    () -> nd.readFileSyscall("/sys/class/android_usb/android0/iSerial"))
    .probe(MMAP, "ro.serialno", "/dev/__properties__", () -> nd.readDevPropertyMmap("ro.serialno"))
```

覆盖的 ~30 项（沿用现有项与显示名）：android_id, serial, model, brand, fingerprint, boot_id, kernel_version, hostname, cpu_serial, cpu_hardware, soc_serial, soc_id, boot_serial, boot_hardware, boot_device, drm_id, vbmeta_digest, build_id, display_id, bootloader, radio, device, board, manufacturer, product, build_type, build_tags, android_version, sdk_level, security_patch, mac_address, total_ram, screen_info, cpu_abi, timezone, language, total_storage, uname_info, gsf_id, cpu_freq, hosts_hash, selinux, proc_name, persistent_token。

> 持久化 Token：保留为一项，但它跨方式同值（非取证比对项），单 probe 显示即可。RAM 等需归一化的项，在 lambda 内部完成归一化后再返回。

## 6. 执行层 FingerprintEngine

```java
FingerprintResult collect(List<FingerprintSpec> specs) {
  for spec in specs:
     item = new FingerprintItem(spec.id, spec.displayName)
     for probeDef in spec.probes:
        try { v = probeDef.collector.collect() } catch { status=ERROR }
        status = classify(v)   // 空/N-A → EMPTY，否则 OK
        item.addProbe(new CollectProbe(method, api, source, v, status))
     item.vote()               // 算 hitValue + outlier + consistent
     accumulate hash by spec.hash tag (用 hitValue)
  result.composite = sha256(所有 hitValue 串)
}
```

- 在后台线程跑（Fragment 已有 executor）。
- 异常隔离：单条 probe 抛错不影响其他。

## 7. UI 层

### 7.1 顶部总览卡（fragment_fingerprint.xml 改）

- **删除**：可信度行 + 进度条 + 篡改状态依赖信任分的部分。
- **改为**：一行 `指纹一致性 28/30 项一致`（不一致时数字标红）。
- 保留：设备指纹 Hash、硬件/软件 Hash 卡。
- **删除**底部"多源比对结果"卡（每项展开已覆盖）。

### 7.2 item_fingerprint.xml（重写）—— 折叠卡

- `MaterialCardView`，**左侧 4dp 色条 + 描边**表示一致性：一致=`status_safe`，不一致=`status_risk`。
- 头部（可点击切换展开）：名称 + 命中值缩写 + 一致性 chip(一致/不一致) + 展开箭头。
- body 容器（`LinearLayout`，初始 `gone`）：由 Adapter 动态注入 probe 行 + 底部汇总 `N 路 · M 一致/K 异常 · 命中 X`。

### 7.3 item_probe.xml（新建）—— 单条探针行

图标(emoji TextView) + 方式名 + 手段/来源(mono small) + 结果值(mono) + 状态点（OK 绿 / 离群红 / 空灰）。

### 7.4 FingerprintItemAdapter（重写）

- 维护 `Set<Integer> expanded`，点击头部 toggle + `notifyItemChanged`。
- `onBind`：按 `isConsistent()` 上色；展开时清空 body 容器并 inflate 每条 `item_probe`。
- 复制按钮复制命中值。

### 7.5 FingerprintFragment（瘦身）

- 删除 `performCollection` 内全部取证代码、`nonEmpty/roundRamValue` 迁移到 Definitions（roundRam 作为私有 helper 或工具）、`ComparisonAdapter`、信任分 UI 绑定。
- `collectFingerprints()`：`engine.collect(FingerprintDefinitions.build(ctx, nd))`。
- 保留：权限请求、持久化读写、`getWidevineDeviceId`（移到 Definitions 闭包或保留为 helper）、hash 展示。

## 8. 颜色/资源

复用 `status_safe`/`status_risk`/`status_safe_container`/`status_risk_container`。新增 drawable：`card_accent_safe.xml`/`card_accent_risk.xml`（左色条），`probe_dot` 状态点复用 `status_dot`。strings 增加：方式名、`probe_consistency_summary`、`fp_consistency_count` 等。

## 9. 改动清单

| 文件 | 改动 |
|---|---|
| `model/ProbeMethod.java` `model/ProbeStatus.java` | 新建 |
| `model/CollectProbe.java` `model/Collector.java` | 新建 |
| `model/FingerprintSpec.java` | 新建 |
| `model/FingerprintItem.java` | 重写为探针模型 |
| `model/FingerprintResult.java` | 删信任分/penalty |
| `fingerprint/FingerprintDefinitions.java` | 新建★（30 项声明） |
| `fingerprint/FingerprintEngine.java` | 新建 |
| `ui/fingerprint/FingerprintFragment.java` | 大瘦身，改用引擎 |
| `res/layout/item_fingerprint.xml` | 重写 |
| `res/layout/item_probe.xml` | 新建 |
| `res/layout/fragment_fingerprint.xml` | 删信任分&对比卡 |
| `res/drawable/card_accent_*.xml` | 新建 |
| `res/values/strings.xml` | 加文案 |
| `model/DetectionLayer.java` | 保留（其他检测模块仍用） |

## 9.5 扩展维度（2026-05-31 增补 · 自证架构可扩展）

调研后新增 11 个维度，全部只在 `FingerprintDefinitions` 加 `define()` 块 + `HwProbe` 加采集源，未改引擎/UI/模型——印证架构目标。

| id | 维度 | 唯一性 | 采集源 |
|---|---|---|---|
| `storage_cid` | 存储芯片 CID (eMMC/UFS) | ⭐每台唯一 | sysfs 多路读（JAVA_FILE/NATIVE/SYSCALL）|
| `sensor_list` | 传感器列表指纹 | 机型级·铁稳 | `SensorManager.getSensorList` |
| `gyro_bias` | 陀螺仪零偏（实验） | 每台近似 | 静止采样均值·1e-3 量化（不进 hash）|
| `gpu_render` | GPU 渲染指纹 | 机型级 | 离屏 EGL `GL_VENDOR/RENDERER/VERSION` |
| `camera_fp` | 相机特性指纹 | 机型级 | `CameraCharacteristics` |
| `media_codec` | 编解码器指纹 | 机型级 | `MediaCodecList` |
| `cpuinfo_hash` | CPUInfo 全量 Hash | 机型级 | `djb2(/proc/cpuinfo)` |
| `input_devices` | 输入设备指纹 | 机型级 | `djb2(/proc/bus/input/devices)` |
| `device_tree` | Device-Tree 标识 | 机型级 | `/proc/device-tree/compatible` |
| `mem_layout` | 内存布局 Hash | 机型级* | `djb2(/proc/iomem,zoneinfo)`（不进 hash）|

> *内存布局：Android 10+ 物理地址被 `kptr_restrict` 抹零，实际熵偏低，仅作机型级参考。
> "固定内存 MD5 当每台唯一指纹"在 App 沙箱不可行（ASLR + 地址抹零 + 沙箱隔离），真正"每台唯一"靠 `storage_cid` 与传感器标定。
> 真·SensorID（标定解算）需静止多姿态采样，非同步探针能稳定产出——`gyro_bias` 为近似版，标注实验性。

新增文件：`util/HwProbe.java`（扩展采集源）。

## 9.6 隐蔽采集维度（2026-05-31 增补 · 调研落地）

按采集顺序深挖隐蔽源，新增 13 项；同时**删除 `persistent_token` 与 `proc_name`**（及对应的存储权限流程）。真机 MEIZU 21/A15 实测命中情况：

| id | 维度 | 采集源 | A15 实测 |
|---|---|---|---|
| `vulkan_fp` | ⭐Vulkan 硬件指纹 | native dlopen libvulkan，VkPhysicalDeviceIDProperties.deviceUUID | ✅ 命中(每台稳定) |
| `battery_fp` | 电池特征 | PowerProfile 反射设计容量 + sysfs 技术 | ✅ 4800mAh |
| `thermal_zones` | 热区列表 | `/sys/class/thermal/thermal_zone*/type` | ✅ |
| `cpu_topology` | CPU 拓扑 | `/sys/devices/system/cpu/cpu*/topology` | ✅ |
| `gpu_caps` | GPU 扩展/能力 | EGL：GL_EXTENSIONS+limits+EGL扩展 | ✅ |
| `audio_fp` | 音频 HAL | AudioManager 采样率/缓冲 | ✅ 48000/192 |
| `prop_set_hash` | 系统属性全量 | 固定 ro.* 集合 djb2 | ✅ |
| `kernel_config` | 内核配置 | gunzip(/proc/config.gz) | ✗ 内核未编 IKCONFIG |

> 环境旁证项（adb/开发者选项/代理/输入法/漫游）一度加入后按需求移除——它们是行为/环境信号而非稳定设备指纹。

**新增原生方法**：`NativeDetector.getVulkanFingerprintNative()`（native-lib.cpp，dlopen 方式不硬链 libvulkan）。
**新增采集源**：`HwProbe` 扩充电池/热区/拓扑/GPU能力/音频/Settings/属性集/内核配置。

> deviceUUID 是本次"每台稳定硬件指纹"的最佳落地——规范保证跨重启/进程/驱动版本不变，且 App 无需权限即可经 Vulkan 取得。

## 10. 验收

- `./gradlew :app:compileDebugJavaWithJavac` 通过。
- 运行后：每项可展开看多路结果；一致/不一致颜色正确；信任分相关 UI 消失；总览显示一致性计数。
- 加一个新指纹只需在 `FingerprintDefinitions` 加一个 `define(...)` 块（设计自证）。
