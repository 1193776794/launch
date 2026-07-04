# libtiny.so 设备指纹采集分析（基于 QBDI 全指令 trace）

> 目标：`/Users/xiaofengfeng/Documents/trace_libtiny.so.bin`（QBDI 全指令 trace）
> 应用：**com.xingin.xhs（小红书）v9.32.0**（versionCode 9320802）
> 主函数：`sub_1B8970`（trace seq 219 进入；IDA 已重命名 `fp_collect_device_1B8970`）
> 模块基址：`0x731461e000`（so_offset = 绝对 pc − 基址；IDA base=0，so_offset == IDA 地址）

============================================== 1 ============================================
---

## json 来源

```
────────── [#3] devfp(设备指纹)  1699B ──────────
  调用方(returnAddress) = libtiny.so+0x1e5dec   RVA=0x1e5dec
  ---- 完整 JSON ----
{"x0":"com.xingin.xhs","x1":"9.32.0","x10":"Redmi/gold/gold:13/TP1A.220624.014/V14.0.11.0.TNQCNXM:user/release-keys","x11":"pangu-build-component-system-298128-6hhzx-3734k-6w6nd","x12":"TP1A.220624.014","x120":"0","x13":"release-keys","x131":"0","x14":"user","x146":"7c8067a81f3f54b2d1e257cd930bb23d496800a9473590e077ac7d8c","x15":"V14.0.11.0.TNQCNXM","x16":"13","x17":33,"x18":"2026-06-05","x185":"IiGgS","x186":-1,"x187":-1,"x19":"gold","x194":"1","x2":9320802,"x20":"Redmi","x202":"1","x203":"1","x206":0,"x207":0,"x21":"arm64-v8a,armeabi-v7a,armeabi","x22":"gold","x23":"Xiaomi","x231":115014074368,"x232":115014074368,"x234":{"1":1715582874664,"2":1715582851796,"3":1715582851672},"x235":4966300,"x236":55558246400,"x237":55558246400,"x238":"cn","x24":"2312DRAABC","x242":[],"x243":1782285462475,"x247":{"0":72.72727272727273,"1":46.666666666666664,"2":47.05882352941177,"3":0.0,"4":80.0,"5":47.05882352941177},"x25":"gold","x258":0,"x259":0,"x26":"aarch64","x260":1782285462973,"x261":1,"x263":0,"x264":0,"x267":0,"x269":1230768000000,"x27":"5.10.198-GKI-Yuri","x272":0,"x28":"#1 SMP PREEMPT Sun Aug 17 16:15:20 UTC 2025","x289":1782285463009,"x29":"MOLY.NR15.R3.MP.V120.3.P48,MOLY.NR15.R3.MP.V120.3.P48","x290":-1,"x293":14696431,"x296":"","x3":1782199052916,"x30":"1080,2400,440","x301":"ABSENT,ABSENT","x302":"","x303":"","x304":2,"x305":-3,"x31":5,"x37":0,"x38":1,"x39":"adb","x4":1782199052916,"x40":1,"x41":"","x42":"","x43":"unknown","x44":1782285462973,"x45":45,"x5":"GooglePlay","x6":1782098607876,"x7":"mt6833","x70":21,"x72":1782208387051,"x73":1782284974620,"x78":10316,"x79":32759,"x8":1715582733000,"x80":922,"x87":1782285462498,"x9":"TP1A.220624.014","x92":35,"x93":3,"x98":"0"}
```

> 结构：serde `BTreeMap` 序列化为 JSON，键按字符串排序，键名全混淆为 `x*`。
> 共 90 键；`⚠️条件性` = 该字段非每次 run 都生成（见末尾「复测」）。
> 采集集中在 `sub_1B8970`：system property 名在栈上逐字符拼 → `__system_property_get`；JNI 调 Android API；uname/statfs/clock_gettime 等少量 syscall；本地 CRC32。序列化/转义循环在 `so_offset 0x163280–0x163298`。

---

## 全字段标记（字段名 / 值 / 来源 / 采集与判断方式）

### A. 应用 / 渠道
| 字段 | 值 | 来源 | 采集与判断方式（地址/细节） |
|---|---|---|---|
| x0 | com.xingin.xhs | 包名 | JNI：Context.getPackageName |
| x1 | 9.32.0 | versionName | JNI：PackageInfo.versionName |
| x2 | 9320802 | versionCode | JNI：PackageInfo.versionCode（数值） |
| x5 | GooglePlay | 安装渠道 | JNI：PackageManager.getInstallerPackageName / 渠道文件 |

### B. 系统构建属性（**现场采集**：属性名 `sub_138D58` 逐字符解密 → 查属性区取值）
> ✅ **机制实锤（fp_collect trace, 816189 指令）**：**现场采集**,不是缓存。每个属性名由 `sub_138D58` **在 trace 里逐字符解密**进栈缓冲(内存可见增长串 `ro.prodi`→`ro.producG`→`ro.product.brand`),解密贯穿整条 trace(seq6118/73364/106738/119461/153902…每个名在用前现场解密)。取值经 `__system_property_get`**读属性区共享内存**——**不走 syscall(userspace mmap 读)也不走 PLT**,故 syscall 表和 `system_property` 搜索都看不到;值由 libc/直接读写入,libtiny 再克隆。
> **内存实锤的属性名**(全部核对):x7=`ro.board.platform`、x9=`ro.build.display.id`、x10=`ro.build.fingerprint`、x11=`ro.build.host`、x12=`ro.build.id`、x13=`ro.build.tags`、x14=`ro.build.type`、x15=`ro.build.version.incremental`、x16=`ro.build.version.release`、x17=`ro.build.version.sdk`、x18=`ro.build.version.security_patch`、x19=`ro.product.device`、x20=`ro.product.brand`、x21=`ro.product.cpu.abilist`、x23=`ro.product.manufacturer`、x24=`ro.product.model`。属性名加密(IDA 搜不到明文),解密后内存明文可见。
| 字段 | 值 | 来源属性 | 采集与判断方式 |
|---|---|---|---|
| x10 | Redmi/gold/gold:13/TP1A.220624.014/V14.0.11.0.TNQCNXM:user/release-keys | ro.build.fingerprint | 直取属性值 |
| x11 | pangu-build-component-system-298128-6hhzx-3734k-6w6nd | ro.build.host | 直取 |
| x12 / x9 | TP1A.220624.014 | ro.build.id / ro.build.display.id | 直取 |
| x13 | release-keys | ro.build.tags | 直取 |
| x14 | user | ro.build.type | 直取 |
| x15 | V14.0.11.0.TNQCNXM | ro.build.version.incremental（MIUI） | 直取 |
| x16 | 13 | ro.build.version.release | 直取（Android 13） |
| x17 | 33 | ro.build.version.sdk | 直取（API 33，数值） |
| x18 | 2026-06-05 | ro.build.version.security_patch | 直取 |
| x19 / x22 / x25 | gold | ro.product.device / ro.board.platform | 直取（设备代号） |
| x20 | Redmi | ro.product.brand | 直取 |
| x21 | arm64-v8a,armeabi-v7a,armeabi | ro.product.cpu.abilist | 直取 |
| x23 | Xiaomi | ro.product.manufacturer | 直取 |
| x24 | 2312DRAABC | ro.product.model（型号串） | 直取 |
| x7 | mt6833 | ro.board.platform / ro.hardware（SoC，MediaTek） | 直取 |

### C. 内核 / 基带
| 字段 | 值 | 来源 | 采集与判断方式（地址/细节） |
|---|---|---|---|
| x26 | aarch64 | CPU 架构 | `uname()` syscall @seq~223414，取 machine |
| x27 | 5.10.198-GKI-Yuri | 内核版本 | uname.release |
| x28 | #1 SMP PREEMPT Sun Aug 17 16:15:20 UTC 2025 | 内核 build 串 | uname.version |
| x29 | MOLY.NR15.R3.MP.V120.3.P48,MOLY.NR15.R3.MP.V120.3.P48 | 基带/调制解调器版本 | property `gsm.version.baseband`（双卡两份） |

### D. 硬件 / 显示 / 存储 / 内存
| 字段 | 值 | 来源 | 采集与判断方式（地址/细节） |
|---|---|---|---|
| x30 | 1080,2400,440 | 屏幕 宽,高,DPI | JNI：DisplayMetrics |
| x231 / x232 | 115014074368（≈107 GB） | 总存储容量 | `statfs(data 分区)` syscall @seq~37652（blocks×bsize） |
| x236 / x237 | 55558246400（≈55 GB） | 可用存储 | `statfs(/sdcard)` syscall @seq~46081 |
| x235 | 4966300（≈4.7 GB，KB） | 总内存 | 读 `/proc/meminfo` MemTotal |
| x247 | {0:72.7,1:46.7,2:47.1,3:0.0,4:80.0,5:47.1} | 6 项浮点指标 | JNI（屏幕/密度/电量类比值，逐槽语义待 taint） |

### E. 时间戳（毫秒）
| 字段 | 值 | 来源 | 采集与判断方式 |
|---|---|---|---|
| x3 / x4 | 1782199052916 | 某事件时刻（2026-06） | JNI System.currentTimeMillis / 文件时间 |
| x6 | 1782098607876 | 较早事件（安装?） | 同上 |
| x8 | 1715582733000 | 2024-05（首装/编译期?） | PackageInfo.firstInstallTime 类 |
| x234 | {1:1715582874664, 2:1715582851796, 3:1715582851672} | 三个 2024-05 时间戳 | 安装/更新/首启 类（嵌套对象） |
| x44 / x243 / x260 / x289 | 1782285462…463…（2026-06，采集时刻） | 采集瞬时 | `clock_gettime(REALTIME)` syscall（多次）+ JNI |
| x72 / x73 / x87 | 1782208387051 / 1782284974620 / 1782285462498 | 各事件时刻 | currentTimeMillis / SystemClock |
| x269 | 1230768000000 | 2009-01-01（固定默认值） | 取不到时的兜底常量 |

### F. 进程 / 计数
| 字段 | 值 | 来源 | 采集与判断方式（地址/细节） |
|---|---|---|---|
| x79 | 32759 | 进程 PID | `getpid()` syscall @seq~310170（**实锤**：返回值即此） |
| x78 | 10316 | 计数/ID（疑 uid 或线程数） | 进程内取值，精确含义待 taint |
| x80 | 922 | 计数 | 同上 |
| x45 / x70 / x92 / x93 | 45 / 21 / 35 / 3 | 各类计数/度量 | 进程内统计，精确含义待 taint |

### G. 地区 / SIM
| 字段 | 值 | 来源 | 采集与判断方式（地址/细节） |
|---|---|---|---|
| x238 | cn | 地区/语言 | JNI：Locale.getCountry |
| x301 | ABSENT,ABSENT | SIM 卡状态（双卡都无卡） | JNI：TelephonyManager.getSimState 逐卡 → 文本 |
| x302 / x303 | ""（空） | 运营商/IMSI 类（无卡为空） | JNI（无 SIM 取不到） |

### H. 标识 / 哈希 / 校验（⚠️条件性，本 run 缺）
| 字段 | 值 | 来源 | 采集与判断方式（地址/细节） |
|---|---|---|---|
| x146 ⚠️ | 7c8067a8…077ac7d8c（56 hex=28B） | 设备哈希/签名 | 本地计算（28 字节摘要，疑 SHA-224；preimage 见末尾「复测」） |
| x185 ⚠️ | IiGgS（另 run 为 IiGgSsKkCVvEePp） | token / 字符集种子 | 本地计算 |
| x99 ⚠️ | 3928694620 | 数值校验和 | **CRC32**：查表 @`so_offset 0x1d48c4–0x1d48e8`（表 `0x731471c000+`），输入 = s* 矩阵串 @`0x726e92c2e0`，结果 @`0x730faf4770` |

### I. 环境 / 调试
| 字段 | 值 | 来源 | 采集与判断方式（地址/细节） |
|---|---|---|---|
| x39 | adb | ADB/调试状态 | 疑 Settings.Global.ADB_ENABLED / build.type 判定 |
| x43 | unknown | 某状态（未判定出/未知枚举） | 进程内判定，含义待 taint |
| x41 / x42 / x296 | ""（空） | 占位/本 run 未取到 | — |
| x242 | [] | 空列表 | 某集合类字段，本 run 为空 |

### J. 数值状态标志（值已知；精确判断逻辑散在混淆代码，需逐项 taint）
| 字段 | 值 | 说明 |
|---|---|---|
| x38 / x40 / x261 | 1 | 布尔“是/开” |
| x37 / x98 / x120 / x131 / x206 / x207 / x258 / x259 / x263 / x264 / x267 / x272 | 0 | 布尔“否/关” |
| x194 / x202 / x203 | "1" | 字符串布尔 |
| x186 / x187 / x290 | -1 | “不可用/未取到”码 |
| x305 | -3 | 错误/特殊码 |
| x31 / x304 | 5 / 2 | 小整数（枚举/计数） |
| x293 | 14696431 | 大数值（疑可用内存 KB / 计数） |

> 共性判断方式：B 类直接读 system property 值，无“判断”；C/D/F 类由对应 syscall 返回值（地址/seq 见上）；H 类本地计算（CRC32 地址已实锤，x146/x185 算法待定）；J 类是风控/环境探测的结果码——**对应的检测逻辑无符号名、散在 ~35 万条混淆指令里，精确“怎么判断”需对各字段写入点逐一 taint（见末尾）**。

============================================== 1 ============================================

============================================== 2 ============================================

## json 来源

```
────────── [#41] id-pkg  1789B ──────────
  调用方(returnAddress) = libtiny.so+0x269fb0   RVA=0x269fb0
  lr @onEnter           = libtiny.so+0x269fb0
  lr @onLeave(不可靠)   = 0x7491ffd10c
  ---- 完整 JSON ----
{"x110":"51bc339b-6346-4202-b6a0-2d2fbbffb7c","x111":"0x337d4cd685007ba5f6bb0d1f6c496bf85f52c4cfc4fd98da368a53cb","x123":"Dalvik/2.1.0 (Linux; U; Android 13; 2312DRAABC Build/TP1A.220624.014)","x128":"","x134":"157f29b9-a1ce-4a1b-b8d9-d605bd0471f4","x137":"65BF9BDF57DAF122EA47643868A699F2","x145":{"com.xingin.xhs":"7c8067a81f3f54b2d1e257cd930bb23d496800a9473590e077ac7d8c"},"x155":"NA349W005842                                                111","x165":{"1":"1782285054500011112-134-64802-0000fd2200000000-4076150800","10":"1782285466056011137-13571328-19-0000000000000000-16914836","11":"1782285462480011137-13566355-19-0000000000000000-16914836","12":"1230768000000000000-229-64769-0000000000000000-1702057286","2":"1782285461604011137-1-157-0000000000000000-16914836","4":"1781883842496000005-3989-64802-0000fd2200000000-4076150800","6":"1782259176948009570-7438-64802-0000fd2200000000-4076150800","7":"1782098637516000001-257-17-0000000000000000-16914836","9":"1782098611432000000-134-17-0000000000000000-16914836"},"x170":"id_provider","x171":"aa3c9779598403b9","x173":"bf2949218a376f5b","x174":"217b5720-95e0-4750-89c4-49db5f99e880","x189":"1781883842496000005-3989-64802-0000fd2200000000-4076150800","x20":"Redmi","x21":"arm64-v8a,armeabi-v7a,armeabi","x231":115014074368,"x232":115014074368,"x236":55558246400,"x237":55558246400,"x25":"gold","x285":0,"x286":"EAACAAgAAgDV0vfLbh43GtJ-jfyImNaOA6KzJAOWSftiCTRqDKx-GhpdgvZFgmlB","x46":"c7ce9db572cecdc4","x47":"63926370-8053-4c35-b0f1-2df84fd3346","x49":"/data/app/~~ilYCmMaClHQW-wbY5OP32Q==/com.xingin.xhs-mUJelfOL4xv9eEn6UDERvA==/base.apk","x68":"50188/W4NJ02351","x69":"NA349W005842","x76":8,"x77":"mt6833","x85":"7a7787eeb9aca4c8ef2418c35c19d194bacb3d82fbff8adf476d6bbfa12a3b55","x86":"F1662FABD856F3718828F89A7F07037DA97760A5"}
```

> 结构：同 #3 一样是 serde `BTreeMap`→JSON，键名混淆为 `x*`，共 ~40 键。本块由 **另一个采集函数**生成（emit 返回地址 `libtiny.so+0x269fb0`，区别于 #3 的 `+0x1e5dec`）。
> 主题是**设备/安装标识符 + APK 校验 + 文件系统时间指纹**（不是 #3 的系统属性快照）。
> 序列化区间 seq ≈ 842k–944k（缓冲 `{"x110":"` @seq842881[序列化 push so 0x13306c]；完整 JSON @seq~942079，长度 1795B）。

> ⚠️ **关于「值」的口径**：trace.bin 是一次**独立 run**，与上面 .md 抓到的 JSON 不是同一次执行。
> 对**每次重生**的字段（随机 UUID / 含瞬时数据的哈希），trace 里的值与上面不同——这正是判断「持久 vs 每次重生」的实锤依据，下表「跨 run」列给出。
> trace run 实测值：x110=`9046d49b-…-e5e38ec5573`、x47=`ac8d2894-…-aa2c2d9b150`、x174=`79caf379-…`、x180=`6aa84e97-…`、x137=`655919F6C1BB15E47D4F27994AEFA18D`；x111/x134/x46/x171/x173/x85/x69/x155/x68/x286 **与 .md 完全一致**。
> ⚠️ 订正：x86、x145 在 trace 中与 .md **不同**（x86 trace=`9835AABDE3B657C1FD365D284555AECB94405195` vs .md=`F1662FAB…`；x145 trace=`7c8037ee200454b2d1e254b4930bb23d4968956947359b147714ff61` vs .md=`7c8067a8…`）。详见下「x86 / x145 专项」——尤其 x145 跨两份样本**同位置共享 7/14 段**，不符合纯哈希特征。

---

## 全字段标记（字段名 / 含义 / 来源 / 采集方式·实锤 / 跨 run）

### A. 标识符——持久（每次 run 不变 ⇒ 设备/安装级稳定 ID）
| 字段 | 值 | 含义 | 采集方式·实锤 | 跨 run |
|---|---|---|---|---|
| x134 | 157f29b9-a1ce-4a1b-b8d9-d605bd0471f4 | 安装级 UUID（36 位标准 UUID） | **最早出现 @seq30067(so 0x4bb56c)**，早于任何 `/proc` 随机源读取 ⇒ 从 app 持久存储（SharedPrefs/文件）读出的「生成一次即落盘」ID | **不变** |
| x171 | aa3c9779598403b9 | `Settings.Secure.ANDROID_ID`（64-bit，16 hex） | JNI；key 串 `android_id` 在栈上构造 @seq11614(so 0x192710)，取回值 @seq123598(so 0x4cf2a8)。归属 `x170="id_provider"` 这组 | **不变** |
| x46 | c7ce9db572cecdc4 | 设备级 16-hex ID（疑 ANDROID_ID 的另一种/旧值或派生） | **极早 @seq11925(so 0x4bb56c)**（紧随 `android_id` 串 @11614(so 0x192710) 之后逐字符拼成 `c7c→c7ce9db…`），从存储/JNI 直取 | **不变** |
| x173 | bf2949218a376f5b | 派生 ID（16 hex=8B） | 在序列化区**晚期生成** @seq822311(so 0x132a28 `str q0,[x19]`)（不是早期读取）⇒ 对前面若干 ID 做本地变换/截断哈希得到 | **不变** |
| x69 / x155 | NA349W005842（x155 尾部补空格 + `111`） | 设备序列号 | **系统属性扫描**：栈上逐字符拼一串候选属性名挨个 `__system_property_get`——`ro.boot.cpuid / ro.boot.deviceid / ro.boot.ap_serial / ro.boot.em.did / persist.radio.serialno / sys.serialno / gsm.serial / vendor.gsm.serial / ro.ril.oem.psno / oem.sno`（seq≈729k–818k 全部可见）。取到非空者即序列号 | **不变** |
| x68 | 50188/W4NJ02351 | 存储硬件 ID（eMMC/UFS 厂商号+型号名） | 同区属性/`sysfs` 探测；本 run 尝试读 `/sys/block/mmcblk0/device/cid`、`/sys/ufs/ufsid`、`/sys/devices/soc0/serial_number` 均 **openat 失败(-ENOENT)**（seq232195/248296/254565，openat svc 同在 so 0x459e3c），最终值来自能取到的属性 | **不变** |

### B. 标识符——每次重生（随机/瞬时 ⇒ 会话级，非设备指纹）
| 字段 | trace run 值 | 含义 | 采集方式·实锤 | 跨 run |
|---|---|---|---|---|
| x47 | ac8d2894-…-aa2c2d9b150 | **boot_id**（每次重启变） | `openat("/proc/sys/kernel/random/boot_id")` **成功**(fd=0x20f @seq102364, openat svc so 0x459e3c)→读出 UUID，值首现 @seq103135(memcpy so 0x4fd478)。读到 36 位后**砍掉末字符**(→`…b1500` 变 `…b150`，35 位) | 同一次开机内不变；**跨重启变** |
| x110 | 9046d49b-…-e5e38ec5573 | **内核随机 UUID**（每次读都变） | `openat("/proc/sys/kernel/random/uuid")` **成功**(fd=0x21d @seq352928, openat svc so 0x459e3c)→内核每次返回全新随机 UUID，值首现 @seq353699(memcpy so 0x4fd478)；同样**砍末字符**为 35 位 | **每次都变** |
| x174 | 79caf379-74c4-4234-91cd-5b8410ccf1ba | 运行期生成 UUID（标准 36 位） | 序列化区**现场生成** @seq822417(memcpy so 0x4fd478)（`UUID.randomUUID` 类 / 又一次 `/proc` 随机读） | **每次都变** |
| x180 ⚠️ | 6aa84e97-cd87-449f-9cf6-407155b12497 | 运行期生成 UUID（**条件性**，.md 此 run 无此键） | 现场生成 @seq822557(memcpy so 0x4fd478) | **每次都变** |

### C. 哈希 / 校验
| 字段 | 值 | 算法/字节 | 采集方式·实锤 | 跨 run |
|---|---|---|---|---|
| x137 | 655919F6C1BB15E47D4F27994AEFA18D（trace run） | **MD5**（32 hex=16B，大写） | **本地 native MD5(libtiny 自带实现)**，详见下「x137 专项」。输入 = **7 个运行期指针值(28B)**，故每 run 必变 | **每次都变** |
| x111 | 0x337d4cd6…368a53cb | **SHA-224**（0x+56 hex=28B） | **非 libtiny 计算**（Java 侧 MessageDigest 经 JNI 回传），libtiny 仅搬运/序列化，详见下「x111 专项」 | **不变** |
| x85 | 7a7787ee…a12a3b55 | **SHA-256**（64 hex=32B，**无 0x 前缀**） | **非 libtiny 计算**：crypto 对 SHA-256 零命中；`trace_value` 对成品串缓冲 `0x73bfffc980` 回溯 writers=[]（插桩外写入）。libtiny 仅 memcpy 搬运(`0x73bfffc980`→`0x720bb7c200`@819730[so 0x4fd410]→`0x720bb7c340`@819952[so 0x4fd438])+序列化@939xxx。与 x111 同源同模式（Java MessageDigest→JNI 回传），仅格式差 `0x` 前缀 | **不变** |
| x86 | F1662FAB…(md) / 9835AABD…405195(trace) | **SHA-1**（40 hex=20B，**大写**） | **非 libtiny 计算**（SHA-1 crypto 零命中）；大写 hex 串在 seq334121(so 0x13306c) 即已成形、一开始就是大写，libtiny 仅用 Rust `String::push` 循环(@`0x132fd8`/`0x13306c`，带 `,` 分隔=可拼多签名)重组后序列化。签名证书 SHA-1，Java/JNI 回传，详见「x86/x145 专项」 | 两样本不同 |
| x145 | {"com.xingin.xhs":"7c80…"}（md/trace 值不同） | 包名→签名证书摘要类（28B=56hex） | **非 libtiny 计算**：源 `0x73816e9d40` 由 memcpy 搬运、无 libtiny 写指令（插桩外/JNI），首现 seq407235(memcpy so 0x4fd468)；libtiny 建 {包名→值} map 再序列化。⚠️ 跨样本同位置共享 7/14 段 ⇒ **疑非纯 SHA-224，而是结构化/自定义摘要**，详见「x86/x145 专项」 | 两样本不同 |

### D. 设备/应用环境
| 字段 | 值 | 含义 | 采集方式·实锤 | 跨 run |
|---|---|---|---|---|
| x123 | Dalvik/2.1.0 (Linux; U; Android 13; 2312DRAABC Build/TP1A.220624.014) | HTTP User-Agent | `System.getProperty("http.agent")` / `WebSettings.getDefaultUserAgent`（JNI），内嵌 model+build.id | 不变 |
| x49 | /data/app/~~ilYC…==/com.xingin.xhs-…==/base.apk | APK 路径 | `ApplicationInfo.sourceDir`（JNI）；`~~xxx==/…==` 段是 Android 每次安装随机化的目录名 | **随安装变** |
| x286 | EAACAAgAAgDV0vfL…vZFgmlB | 内嵌/存储 token（61 char，base64url 形态） | 从存储/资源取出 @seq822704(memcpy so 0x4fd438)，原样写入 | 不变 |
| x170 | id_provider | 该 ID 分组的**字面量标签** | 代码常量（非采集），标注后面 x171 等 ID 的 provider 名 | 常量 |
| x20/x21/x25/x77 | Redmi / abilist / gold / mt6833 | 品牌·ABI·设备代号·SoC | 同 #3（`ro.product.*` / `ro.board.platform`，属性直取） | 不变 |
| x231/x232/x236/x237 | 115014074368 / 55558246400 | 总/可用存储 | 同 #3（`statfs`，trace 内 statfs 实锤 @seq279797(svc so 0x2ce1f0) 等多次） | 不变 |

### E. 文件系统时间指纹（x165 / x189）——逐字段完全展开

x165 是对**一组固定路径**逐个做 `fstatat`+`statfs`、把结果拼成字符串的 map。trace 内 fstatat/statfs **各 18 次**（seq 266k–724k；fstatat svc so 0x2a0670、statfs svc so 0x2ce1f0），其中主连续轮（seq 607584→661544）正好按代码里的路径数组顺序走 12 条，**数组下标 = x165 的键号**。

#### E.1 值字符串的 5 段格式（`A-B-C-D-E`）
以 key `10`（=`/dev/fd/1`）实例 `1782285466056011137-13571328-19-0000000000000000-16914836` 为例：

| 段 | 字段名 | 取自 | 含义·实锤 |
|---|---|---|---|
| **A** | `st_mtim` 纳秒整数 | fstatat | `mtime_sec×10⁹ + mtime_nsec`（19–20 位）。前 13 位 = 标准 ms 时间戳（与 #3 的时间戳同量纲）。`1230768000000000000` = **2009-01-01 兜底**=mtime 取不到 |
| **B** | `st_size` | fstatat | 文件字节数。目录→小值；`/dev/fd/0、1`→**13.5 MB**（=正被写入的 QBDI trace 文件本身） |
| **C** | `st_dev` | fstatat | 设备号(十进制)。`64802=0xFD22`(f2fs userdata 253:34)、`64769=0xFD01`、`17/19/157`(tmpfs/匿名 fs) |
| **D** | `statfs f_fsid` | statfs | 64 位 16-hex。**仅真实 f2fs 分区非零**=`0000fd2200000000`(即 0xFD22)；fuse/tmpfs/失败=全 0 |
| **E** | `statfs f_type` | statfs | 文件系统魔数。**`1702057286=0x65735546="FUSE"` 实锤**(/sdcard)；`/data`=f2fs 系魔数 `4076150800`；tmpfs 类=`16914836` |

> ⚠️ stat/statfs 结构体由内核写入，QBDI **不合成二进制结构写**（仅合成字符串型），故内存里读到的 struct 多为栈上残留——**值的地面真相是 libtiny 拼出的这串本身**，不是 struct 内存。本表语义由「输出值 + 路径语义 + FUSE 魔数精确命中」反推得出。

#### E.2 键号 ↔ 路径（12 条全表，trace 实锤路径）

| key | 路径 | fstatat 结果 | .md 中 x165 值 | 语义 |
|---|---|---|---|---|
| 1 | `/data/system` | ok | 1782285054500011112-134-64802-0000fd2200000000-4076150800 | 系统目录，f2fs，mtime=采集当日 |
| 2 | `/data/data/` | ok | 1782285461604011137-1-157-0000000000000000-16914836 | 应用数据根，mtime 极新 |
| **3** | `/data/data/com.android.shell` | **失败 -2(无权限)** | **(键缺失)** | 探测 **adb shell 包**是否可 stat（root/调试探测） |
| 4 | `/data/system/install_sessions` | ok | 1781883842496000005-3989-64802-0000fd2200000000-4076150800 | **安装会话目录**，mtime=最近一次装/更新(2026-05-30)。**x189 单独取的就是这条** |
| **5** | `/data/data/com.google.android.webview` | **失败 -2** | **(键缺失)** | 探测 WebView 包目录 |
| 6 | `/data/data/com.google.android.gms` | ok | 1782259176948009570-7438-64802-0000fd2200000000-4076150800 | **GMS(Google 服务)** 目录，存在性+时间→真机/GMS 指纹 |
| 7 | `/dev/__properties__/u:object_r:radio_prop:s0` | ok | 1782098637516000001-257-17-0000000000000000-16914836 | property 区文件，dev17(tmpfs)，mtime=**开机时刻**(2026-06-01) |
| **8** | `/dev/__properties__/u:object_r:ffs_prop:s0` | **失败 -2** | **(键缺失)** | USB **ffs(functionfs)** 属性区 |
| 9 | `/dev/__properties__/u:object_r:debuggerd_prop:s0` | ok | 1782098611432000000-134-17-0000000000000000-16914836 | debuggerd 属性区，mtime=开机时刻 |
| 10 | `/dev/fd/1` | ok | 1782285466056011137-13571328-19-0000000000000000-16914836 | 进程 **fd1(stdout)** 指向的文件，size=13.5MB |
| 11 | `/dev/fd/0` | ok | 1782285462480011137-13566355-19-0000000000000000-16914836 | 进程 **fd0(stdin)** 指向的文件，size=13.5MB |
| 12 | `/sdcard` | ok | 1230768000000000000-229-64769-1702057286 | 外置存储，**FUSE**(E=0x65735546 实锤)；mtime 兜底 2009 |

> **闭合验证**：缺失的 keys **3 / 5 / 8** ⇔ trace 中 fstatat 返回 `-2`(ENOENT/EACCES) 的三条路径，一一对应 ⇒ 映射可靠。
> **指纹用途**：这组路径混合了「安装时刻」(install_sessions=x189)、「开机时刻」(property 文件)、「GMS/WebView/shell 包存在性」、「外存类型(FUSE)」与「自身 fd 指向」。靠 **mtime 纳秒精度 + 设备号 + fs 类型** 拼出的组合极难被改机/多开伪造，是一个抗篡改的环境指纹。

#### E.3 x189
| 字段 | 值 | 含义 |
|---|---|---|
| x189 | 1781883842496000005-3989-64802-0000fd2200000000-4076150800 | **= x165 的 key `4`**，即 `/data/system/install_sessions` 的 stat 指纹，单独拎出来强调——其 mtime 纳秒值 = **本机最近一次应用安装/更新时刻**，作为独立的安装指纹字段 |

### F. 数值 / 占位
| 字段 | 值 | 说明 |
|---|---|---|
| x76 | 8 | 小整数（枚举/计数，含义待 taint） |
| x285 | 0 | 布尔「否/关」 |
| x128 | "" | 空串（本 run 未取到/占位） |

---

## 旁路发现：自保护子进程（socketpair + fork/exec）

序列化前 seq≈396005–398318，libtiny 起了一个**子进程**做完整性/dex 校验，全程 syscall 实锤：

- `socketpair @seq396005`(svc so 0x2646a8) 建父子通道；随后多次 `write/read` 交换数据。
- 父进程通过 socket **下发两条路径**（`get_memory` 读出）：
  - `…/com.xingin.xhs-…==/lib/arm64`（native 库目录，@seq396830[write svc so 0x27df84] 写 0x56B）
  - `/data/user/0/com.xingin.xhs/app_cache/c4d121c215evx1s51d.dex`（**运行期解密落盘的 dex**，@seq396483[write svc so 0x27df84] 写 0x3c B）
- 期间读取系统 **BOOTCLASSPATH**（`/apex/.../bouncycastle.jar:…:framework.jar:…` 长串 @seq373825[memcpy so 0x4fd248]）。
- 子进程结束用 `wait4 @seq398223`(svc so 0x27d908，收到 pid 0x7f9a) + `kill(pid,9) @seq398127`(svc so 0x27d888) 收尾。

这是 libtiny 的**壳/dex 加载 + 环境校验**逻辑，结果可能影响 #3 里 x37/x38… 等环境标志位，但本身不直接对应 JSON#2 字段。

## x137 专项：MD5(7 个运行期指针) = 每次启动重生的会话随机 token

逐指令 trace 还原出的完整链路：

1. **算法 = libtiny 自带 native MD5**。压缩函数 `MD5Transform` @so `0x4524ec`（绝对 `0x74986bc4ec`），轮常量 `0xd76aa478 / 0xe8c7b756 / 0x242070db / 0xc1bdceee` 实锤；init 向量 `0x67452301/efcdab89/98badcfe/10325476` 实锤。crypto 魔数扫描高置信命中 @seq402182–402220(MD5Transform 体内，so 0x452544 起)。
2. **被哈希的输入 = 28 字节 = 7 个小端 32 位值**。MD5 块指针 x1=`0x7492f49038`，x2=`0x40`(单块)；读出 M[0..6] = `0x6fb51c30, 0x6fb51a70, 0x6fb51b30, 0x6fb51b90, 0x6fb51af0, 0x6fb51c50, 0x6fb51a10`，第 28 字节起为 `0x80` MD5 填充 ⇒ 原文恰好 28B。
3. **这 7 个值是指针**：全部落在同一个 4KB 页 `0x6fb51000` 内（偏移 a10/a70/af0/b30/b90/c30/c50，彼此相差 0x20–0xa0），是 7 个**顺序分配的堆对象地址**。页基址受 ASLR 随机化 ⇒ 每次进程启动都不同。
4. **数据如何到达 MD5**：MD5 wrapper @so `0x452460` 调 `memcpy`(实现 @`0x4fd068`，字拷贝循环 `ldr w11,[x10],#4`/`str w11,[x9],#4` @`0x4fd474`)，把源 `0x74989b8eb0` 的 28B 拷进 MD5 输入块。源缓冲由未插桩 callee 填充；taint 链回溯到 `clock_gettime`→`madd x0=sec*1000+ms`(当前毫秒 `0x19efd998cb3`)的时间种子计算。
5. **输出 = 大写 hex**。16B digest 在 seq 403478–403614(hex-push 循环 so 0x13306c) 被逐字符转成 32 位大写 hex（缓冲 `0x74989b8f00`，紧邻输入源），成品串 `655919F6C1BB15E47D4F27994AEFA18D` @seq404279(so 0x13306c)，最终在序列化区 @seq858597(序列化循环 so 0x163280–0x163298) 写入 JSON 的 `x137`。

**结论**：x137 **不是设备指纹**，而是每次采集**现场生成的会话级随机 token**——用「7 个堆指针地址(ASLR 熵) + 时间种子」喂 MD5 得到。与 #3/#2 里那些稳定哈希(x111/x85/x86=稳定标识符摘要)性质相反，x137 跨 run 必变，可作为本次上报的 nonce/请求标识，无法用于跨会话识别设备。

## x111 专项：SHA-224 设备摘要——在 Java 侧算好、JNI 回传，libtiny 只搬运

逐指令 trace 的结论（与 x137「native 自算」形成对比）：

**已实锤**
1. **形态 = SHA-224**：`0x` + **56 位小写** hex = 28 字节，正是 SHA-224 摘要长度；跨 run 完全一致（.md 与 trace 同值）⇒ 输入全为稳定项。
2. **libtiny 没有计算它**：① `analyze_crypto` 对 SHA-1/SHA-224/SHA-256 **零命中**（全 trace 只有 CRC32、MD5 两种 native 算法）；② `trace_value` 对成品串缓冲回溯，**找不到任何 libtiny 写指令**（writers=[]，提示「被未插桩 callee 写入」）。
3. **libtiny 只做搬运 + 序列化**：成品串常驻堆对象 `0x7493dc1040`（结构 `{tag@+0x28=0x41, len@+0x30=0x3a(58), ptr@+0x38=0x7493dc1000}`，是 Rust 风格 String/枚举）。libtiny 用自带 memcpy(@`0x4fd068`) 把它从 `0x7493dc1000` 拷到 `0x73fd135280`(seq749277–749330，memcpy so 0x4fd410→0x4fd494)、再拷到 `0x71e0301600`(seq749558，同 memcpy so 0x4fd494)，最后在序列化区 @seq846xxx(序列化循环 so 0x163280–0x163298) 逐字符写进 JSON 的 `x111`。整页 `0x7493dc1xxx` 在 QBDI 内存里全 `unknown`（内容由插桩外代码写入）。

**高置信推断（preimage 不在 native trace 内）**
- `0x` + 小写 hex 的拼法是 **Java/Kotlin 习惯**（典型 `"0x" + BigInteger(1, digest).toString(16)`）；native C 几乎不会给哈希加 `0x` 前缀。结合「无 native SHA + 串来自插桩外」⇒ **x111 由 Java 层 `MessageDigest.getInstance("SHA-224")` 对一组稳定设备标识做摘要**，成品字符串经 JNI 下传给 libtiny。
- **同模式**：x85(SHA-256,32B)、x86(SHA-1,20B)、x145/x146(签名证书 SHA-224) 都同样「native 无魔数 + 串插桩外生成」，均为 Java/JNI 回传的稳定摘要。
- **要拿到被哈希的原文**（到底拼了 ANDROID_ID / 序列号 / boot_id 等哪些字段）：本 native trace 看不到，需 **Frida hook `java.security.MessageDigest.update()/digest()`** 或 app 的 Kotlin 摘要函数，dump 其 `update` 输入字节。

## x86 / x145 专项：签名证书摘要类——同样 Java/JNI 回传，libtiny 只做字符串重组

两者都是「APK 签名相关摘要」，与 x85/x111 同属 **native 不计算、Java 侧算好回传** 的族；但 trace 处理细节不同，且都暴露出「跨样本不一致」的反常。

**x86（SHA-1，大写 40-hex）**
- `analyze_crypto` 对 SHA-1 **零命中** ⇒ libtiny 内无 native SHA-1。
- 大写 hex 串 `9835AABD…405195` 在 **seq334121(so 0x13306c)** 的栈缓冲 `0x7492f48cb0` 即已成形，且**全程只有大写、无小写版**（排除 libtiny 做 `to_uppercase` 的可能）。
- libtiny 对它只做 **Rust `String` 重组**：`String::push` 单字符循环 @so`0x132fd8`/`0x13306c`，并在 `0x133050` 写入分隔符 `,`（说明这是个**可拼接多签名**的列表，单签名时即一条）；多次 push/collect 后写进 JSON。
- ⇒ x86 = **签名证书 SHA-1**，由 Java(`MessageDigest("SHA-1")` / `Signature.toByteArray`→hex 大写) 经 JNI 回传，libtiny 仅重组+序列化。

**x145（{包名: 56-hex}）**
- 成品串 `7c8037ee…ff61` 的源缓冲 `0x73816e9d40` 经 libtiny 自带 memcpy 搬运，**trace_value 回溯 writers=[]**（插桩外/JNI 写入），首现 **seq407235(memcpy so 0x4fd468)**（紧邻 MD5 区，早于 x85/x111 的 819k）。
- libtiny 把它组织成 **{包名 → 摘要} 的 map** 再序列化（与 #3 的 x146 同形）。
- ⚠️ **反常**：把 .md 与 trace 两份 x145 按 4 字符分组对齐，**7/14 组在相同位置完全相同**（`7c80 / 54b2 / d1e2 / 930b / b23d / 4968 / 4735`），其余组不同：

  ```
  .md   : 7c80 67a8 1f3f 54b2 d1e2 57cd 930b b23d 4968 00a9 4735 90e0 77ac 7d8c
  trace : 7c80 37ee 2004 54b2 d1e2 54b4 930b b23d 4968 9569 4735 9b14 7714 ff61
          ^^^^      .... ^^^^ ^^^^ .... ^^^^ ^^^^ ^^^^ .... ^^^^ .... .... ....
  ```
  两个**真正的 SHA-224** 在相同位置共享一半字节，概率约 16⁻²⁸，**实际为 0** ⇒ x145 **不是对固定输入的纯 SHA-224**：要么是「固定字段(证书部分) + 变动字段」的**结构化编码**，要么是分块/带盐的自定义摘要。

**结论与待办**
- x86、x145、x85、x111、x137(对照) 这组「哈希型」字段中，**只有 x137 是 libtiny native 自算**（MD5 of 指针，随机）；x85/x111/x86/x145 的摘要全在 **Java 侧**完成，libtiny 只搬运/重组/序列化——native trace 看不到它们的 **preimage 与真实算法**。
- x145 的位段反常**必须**用 Frida 验证：hook `MessageDigest.update/digest` 与 `PackageInfo.signatures` 处理逻辑，dump 输入字节，确认它到底是 SHA-224 还是结构化编码、以及为何跨样本变化。

> 复测/待 taint：x46 与 x171 的精确区分（两者都是稳定 16-hex ID，x46 极早 @11925、x171 来自 ANDROID_ID @123598——是否 x46= ANDROID_ID 旧缓存、x171= 实时取值，需对二者写入点 taint）；x111/x85/x86 的摘要**输入拼装顺序**（off-trace 计算，需 hook Java `MessageDigest`）；x173 由哪几个 ID 派生（对 @822311 写入点 taint）；x165 各槽对应的**具体路径表**（对 18 个 fstatat 的 path 参数逐一 dump）。

============================================== 2 ============================================

============================================== 3 ============================================

## json 来源

```
────────── [#47] detect-bitmap(d/s位图)  304B ──────────
  调用方(returnAddress) = libtiny.so+0x30e4a4   RVA=0x30e4a4
  lr @onEnter           = libtiny.so+0x30e4a4
  lr @onLeave(不可靠)   = 0x7491ffd10c
  ---- 完整 JSON ----
{"d1":"109|110|117|129","d10":"","d11":"7|8|9","d12":"","d13":"","d4":"","d6":"","d9":"","s1":"0|0|-|0|0|0|0","s10":"0|*|0|*|*","s11":"*|0|0","s2":"1|*|0","s3":"*|0|0|0|0|0|0","s4":"*|*|*|*","s5":"0|*|*|*|0|0|0|0|0|*|0|0","s6":"*|0|0|*|0|0|0|0|0|*|0|-","s7":"0|0|0|0","s8":"0|-|0|0|0|0|0","s9":"*|0|-|0"}

{"d1":{"109":["","[0]/sdcard/Android/me.weishu.exp"],"110":["","[0]/sdcard/Android/org.lsposed.manager"],"117":["","[0]/dev/input/event0"],"129":["","[0]/mnt/vendor/persist/magisk"]},"d11":{"7":["find ro.build.version.sdk = [33]"],"8":["find ro.product.brand = [Redmi]"],"9":["find gsm.sim.state = [ABSENT,ABSENT]"]},"global":{"code-patch-check":["detect tiny code patch!","hash[0] = 10958256408504113051 hash[1] = 11057368107246415373","hash[0] = 18263822059593124258 hash[1] = 12279844574111463802","hash[0] = 15332282080088673517 hash[1] = 3212966154718522854","hash[0] = 8895746125068715691 hash[1] = 1130296871999799244","hash[0] = 2787493050953718138 hash[1] = 11256148952258623959","hash[0] = 17839776398586908277 hash[1] = 17347767422769032550","hash[0] = 9961858140561016555 hash[1] = 18011371367030266250","hash[0] = 5526516740950123890 hash[1] = 6106420274630025974","hash[0] = 872479220511054815 hash[1] = 6771765564968651864"],"code-patch-prepare":["","sections[0] = 0x000000731ed23ec0 - 0x000000731ed24a00","sections[1] = 0x000000731e750900 - 0x000000731e762160","sections[2] = 0x000000731e78e358 - 0x000000731ed23eb8","sections[3] = 0x000000731e762160 - 0x000000731e76a6f4","sections[4] = 0x000000731e76a6f8 - 0x000000731e78e354","sections[5] = 0x000000731e65d288 - 0x000000731e65e6b0","sections[6] = 0x000000731e65efa0 - 0x000000731e65f909","sections[7] = 0x000000731e65f910 - 0x000000731e74f838","sections[8] = 0x000000731e74f838 - 0x000000731e7508e8"]},"s1":{},"s11":{},"s6":{"3":["1"],"9":["","FD 7B BF A9"]},"s7":{"4":["","package name: com.xingin.xhs"]},"t":{"10":["","[3] _ZN3art2gc4Heap18GrowForUtilizationEPNS0_9collector16GarbageCollectorEm [/apex/com.android.art/lib64/libart.so 0x3787d0] hooked by [0x40 0x00000073efd38040] with maps [0x73efd38000 ] [arm64] [1C FE F6 17 E9 23 01 6D FD 7B 02 A9 FD 83 00 91 FC 6F 03 A9 FA 67 04 A9 F8 5F 05 A9 F6 57 06 A9 F4 4F 07 A9 59 D0 3B D5 F3 03 00 AA 28 17 40 F9]","[3] _ZN3art2gc5space13FreeListSpace5AllocEPNS_6ThreadEmPmS5_S5_ [/apex/com.android.art/lib64/libart.so 0x3b1590] hooked by [0x10 0x00000073efd38010] with maps [0x73efd38000 ] [arm64] [A0 1A F6 17 FD 7B 03 A9 FD C3 00 91 FC 6F 04 A9 FA 67 05 A9 F8 5F 06 A9 F6 57 07 A9 F4 4F 08 A9 E3 0B 00 F9 5B D0 3B D5 14 C0 04 91 F5 03 00 AA]"],"12":["","[4] __dl___loader_android_dlopen_ext [/apex/com.android.runtime/bin/linker64 0x370b0] hooked by unknown hooker 0x0000007491ffd000 [arm64] [50 00 00 58 00 02 1F D6 00 D0 FF 91 74 00 00 00 F4 4F 03 A9 F7 03 00 AA A0 07 00 90 00 80 17 91 F3 03 03 AA F5 03 02 AA F6 03 01 2A 49 A5 03 94]"],"15":["","C0 03 5F D6","ret [arm64 0xD65F03C0]"],"21":["[] [] []"],"24":["76.944584 397111 5161"],"26":["","/data/data/com.xingin.xhs","/data/data/./../user/0/com.xingin.xhs","/proc/self/maps"],"27":["","[u] 7491ee6000-7491ee7000 rwxp 00000000 0                                     [anon:shadowhook-enter]","[u] 7491ee7000-7491ee8000 rwxp 00000000 0                                     [anon:shadowhook-hub-trampo]"],"7":["detect byte-hook trampoline for function[1] address 0x0000007491eb6f50: [0x0000000000000f50] [anon:bytehook-plt-trampolines]"]}}
```

> 结构：两段同源。**上段=压缩位图(detect-bitmap, cap/detect-bitmap_30e4a4.json)**，**下段=展开详情(detect-detail, cap/detect-detail_30e750.json)**，是同一棵检测结果树的两个视图。emit 返回地址 `libtiny.so+0x30e4a4`，顶层采集发生在 `detect_report_thread_loop`(0x3110a4)。
>
> 🔒 **这棵 detect-detail 树同时被白盒加密成 devfp 的 `x295` 字段**（见 §「x295 专项」）：明文经 `json_ser_new` 序列化成上面这段 JSON，再由 `sub_6B4558` 白盒加密 → base64 → x295。即 **x295 = detect-detail 的加密上报副本**，长度随发现量变化。

---

## 检测上报机制全链路（frida 实测 + IDA + trace 三方交叉印证）

### 顶层：8s 轮询上报线程
`detect_report_thread_loop`(0x3110A4，`__noreturn`，由 `sub_44BF08` 起 pthread)每轮：①初始化 ctx(`qword_748F48`) ②`pthread_mutex_lock` ③`run_all_detections`(0x31344C) 跑全部检测填 ctx ④`value_deepcopy_serialize`(0x26DF58)×4 把结果深拷贝+混淆指针 swap 进全局上报对象(`byte_749430`/`qword_748F48`/`byte_7494E0`) ⑤解锁 ⑥`clock_gettime` 时间戳 ⑦`nanosleep(8s)` 休眠。

### 派发链：run_all_detections → 15 wrapper → 派发器 → 19 叶子（全间接）
- **派发器** `sub_42F2D4(ctx, a2=enable_bit, a3=数字key, a4=functor)`：`sub_13377C(a3)` itoa 成 map key → `serde_map_insert` 占位 → 查使能位图 `(enable>>a2)&1` → 启用则 `(**a4)()` 即 **future->vtable[0]() BLR@0x42F390** poll 进叶子检测器，结果(type=3 变体)写回 map；未启用填默认 `"-"`(`json_value_from_cstr(&qword_749018)`)。
- **15 个 wrapper**(`xrefs_to 0x42F2D4`)：`sub_3F2EF0/3FC73C/3FC7AC/403118/40A05C/40A82C/40BE0C/40C510/40D364/40D6F0/40E078/4169D4/…`，彼此**尾调用**成 future 链，各传一组 `(bit,key,functor)`。
- **静态调用图为空**（派发全间接 BLR），只能动态追。frida hook `BLR@0x42f320`/派发器入口 → **实机抓到 19 个叶子检测器**：

| 数字key | bit | 检测器(so_offset) | 检测内容(frida 实测) |
|---|---|---|---|
| 0(global) | — | 完整性 | dump `.text` sections[0..8]+hash → `detect tiny code patch!` |
| 3 | 0 | 0x435774 | 线程/proc 反插桩快校验 → `"1"` |
| 4 | — | — | 包名核对 `package name: com.xingin.xhs` |
| 7 | 1 | 0x435380 | **bytehook/PLT trampoline** `[anon:bytehook-plt-trampolines]` |
| 8 | 2 | 0x434fac | `__system_property_*` inline-hook 完整性 |
| 9 | — | — | 函数序言字节 `FD 7B BF A9` |
| 10 | 3 | 0x434d10 | **ART/libart inline-hook 扫描**（列 art::gc::Heap*/ThreadList 被 hooked + 覆盖字节） |
| 11 | 4 | 0x434988 | libc(sched_yield)maps hook |
| 12 | 5 | 0x4346e0 | **linker64 hook**（`__dl___loader_android_dlopen_ext`） |
| 14 | 6 | 0x433b94 | ART 运行时符号 inline-hook 扫描 |
| 15 | 7 | 0x433894 | 函数被改 ret 检测 `ret 0xD65F03C0` |
| 16 | 8 | 0x4337c4 | 反射 ActivityManager/Intent 被 hook 探针 |
| 17 | 9 | 0x433510 | uname.release 内核签名(模拟器) |
| 18 | 10 | 0x433460 | java/util/Map 方法ID hook 检测 |
| 19 | 11 | 0x432d5c | (本轮无输出) |
| 20 | 12 | 0x432ab4 | /lib64/libmediandk.so 映射标记 |
| 21 | 13 | 0x431810 | JNI 输入/监听器枚举 `[4098][TOOL_TYPE_FINGER(1)][0]` |
| 24 | 14 | 0x431324 | 内存页写入计时基准(模拟器指纹) `59.9.. cycles..` |
| 26 | 15 | 0x430a28 | /data/data/<pkg> 可访问性扫描 |
| 27 | 16 | 0x4306f0 | **shadowhook 检测** `[anon:shadowhook-enter/hub-trampo]` |
| 29 | 17 | 0x430394 | JNI Java 层查询 |
| 30 | 18 | 0x42f654 | **root su 路径扫描**(直接 SVC) |

### 上报字段语义（detect-bitmap / detect-detail / devfp 三类合一）
- **`x*`** = 设备指纹采集(见 section 1/2，`pkg_*.json`)。
- **`d1..d13`** = **命中条目 ID 列表**(变长)。值 `"109|110|117|129"` = 该类**命中的黑名单条目 ID**；每 ID 对应一个固定探测目标。空串=该类零命中。**ID = 该条目在黑名单表里的索引**（实测 `me.weishu.exp`=109/`lsposed`=110/`event0`=117/`magisk`=129，ID 与日志行号偏移一致）。
- **`s1..s11`** = 检测器结果 **bitmap**(定长逐位)：`0`=未中、`*`/`1`=命中、`-`=未启用。编码字典由 `sub_138D58`(字符串常量池初始化器)解密：`qword_749030="0"`/`qword_749048="1"`/`qword_749018="-"`。
- **`t`** = 本轮命中的检测器 key 汇总(如 `{7,10,12,15,21,24,26,27}`)。
- **`global`** = 代码完整性(`code-patch-prepare`/`check`)。

### category 路径机制（hook sub_3ECF04 实测）
叶子命中时 `sub_3ECF04(ctx, flag, value)` 沿**预设路径**往目标 d-list 追加字符串。路径由 ctx 路径段决定：`ctx+0x30`=数字 key(id，可为 -1)、`ctx+0x58`=路径段数组(每段首 8B=char* 段名)。实测每条命中带 `[category/id]`：`[d1/109]=me.weishu.exp`、`[d11/7]=sdk=33`、`[s6/9]=FD 7B BF A9`、`[t/26]=/data/data/...`。

### d1 实例：Xposed系 + Magisk系 Hook/Root 框架痕迹
本轮 d1 命中 4 条(ID 109/110/117/129)。ID 稀疏(110→117→129)说明 **111–116、118–128 是 d1 名下未命中的检测**=Xposed(edxposed.manager/XposedBridge.jar/libxposed_art.so/app_process_xposed)、Magisk(magisk64/magiskhide/.magisk/zygisk/riru/.core)等。d1 约 20+ 条(ID≈109–129)。

### 共享路径黑名单（sub_265E24，frida 全量 dump 460 条）
所有路径类检测过 `sub_265E24(const char *path, char *out)`（多手段 SVC 探测：fstatat/statfs/faccessat/openat/socket-bind，躲 libc hook；`out[0]=0` 表 stat 命中）。frida hook 实测**460 条候选**(244 命中，研究机装了 magisk+lsposed+edxposed+taichi)，覆盖：su 二进制(~95条)、模拟器(qemu/goldfish/bluestacks/nox/genymotion/droid4x/houdini/vbox)、Xposed系、Magisk系、云手机(redfinger/migu/longene/haima)、docker/lxc/virtio。黑名单+category 是**哈希表/配置驱动**(trace 实测调用者 `sub_42B078` 是 DJB2-hash 查找；`find_regex` 对 `d1`/路径串零命中=运行期解密)，故静态无明文 xref。

### frida 脚本（本会话产出，位于 frida/）
- `hook_map.js`：派发器(key↔bit↔detector)+ ctx 写入(数字key↔值)。
- `hook_sd.js`：压缩报告 REP1/REP2 字段名+顺序(sub_2715E0)。
- `hook_d1.js`：sub_265E24 全量路径黑名单 dump。
- `hook_cat.js`：sub_3ECF04 命中条目 category 标注 `[category/id]=value`。
- `hook_global.js`：sub_3ECF04 命中时抓调用栈回溯,定位各 category 的检测器主体函数。

---

## global 专项：代码完整性自校验 = xxHash3-128（QBDI replay trace 实锤）

`global` 类（`code-patch-prepare` + `code-patch-check` + `detect tiny code patch!`）是 libtiny 对**自身 `.text` 做分段哈希自校验**，检测是否被 inline-patch / hook。它是 key=0、在 dispatch 19 叶子之前**内联**跑的。

### 定位（frida 回溯 + IDA + trace 三方）
- **检测器入口 = `sub_3EB6C0`**（hook_global.js 回溯命中 `#1 libtiny+0x3eb868`；`sub_3EB7D0` 只是它被平坦化截断的中间块）。
- 调用关系：
  ```
  sub_3EB6C0  (global 完整性检测器, cxa_guard 一次性, 整体 OLLVM 控制流平坦化)
  ├ sub_3EC4B8        加载期一次性初始化(pipe2+分配) → 算并存基准 hash
  ├ sub_3EC940        收集自身 9 段 .text 范围 → vector(每段 {start,hi}, push=sub_43E860)
  ├ sub_2757F0/275988 ★ XXH3 哈希核(逐段算 128bit hash)
  ├ sub_42A088        ctx 路径定位到 "global"
  ├ sub_42A5D0        变体节点清理(非哈希)
  └ sub_3ECF04 ×3     写 sections[0..8] / 各段 hash[0]/hash[1] / "detect tiny code patch!"
  ```

### 哈希算法 = xxHash3-128（实锤）
对 `0x3EB6C0` 单独做 QBDI replay trace（66M 指令，大部分其实是后续 460 条路径黑名单的 syscall 扫描 @`0x45dxxx`；global 哈希集中在早期）。哈希内核在 **so_offset `0x275dbc–0x275e4c`**（trace seq≈2M），指令序列是 XXH3 的 `accumulate_512` 标志步：

```asm
; 标量路径
ldp    x0, x3, [x15,#0x10]            ; 读 64bit 数据字(被哈希的 .text)
ldp    x1, x2, [x16,#0x30]            ; 读 secret/key 字
eor    x0, x0, x1                      ; data ^ key
lsr    x4, x0, #0x20                   ; 取高 32
umaddl x14, w0, w4, x14                ; acc += (u32)low × (u32)high   ← XXH3 标量 mul-acc
; SIMD 路径(并行 2 lane)
eor    v5.16b, v6.16b, v5.16b          ; data ^ key (通道)
xtn    v6.2s, v5.2d                    ; 拆低 32
shrn   v5.2s, v5.2d, #0x20             ; 拆高 32
umlal  v7.2d, v6.2s, v5.2s             ; acc.2d += low32 × high32     ← XXH3 向量 mul-acc
add    v2.2d, v7.2d, v2.2d             ; 累加进 128bit 状态(2×64)
```

**判定**：`通道XOR → xtn/shrn 拆低高32 → umlal(低×高)累加进 2×64bit → add 进状态` 这套组合，加上标量 `umaddl w_low,w_high`，是 **xxHash3 / XXH3** 的 accumulate 核心；128bit 状态 → 输出 `hash[0]`/`hash[1]`。**不是 CRC32 / MD5**（那两个是 libtiny 别处的 x99/x137，见 section 1/2）。`analyze_crypto` 报的 "xxHash" 为真；同时报的 "FNV/CityHash" 是噪声（FNV magic `0x00000100` 误命中每条 `str x15` 栈写）。

### 工作流程
1. **加载期**(`sub_3EC4B8`)：对 9 段 `.text` 各算一次 XXH3-128，存为**基准**。
2. **每轮检测**(`sub_3EB6C0`)：`sub_3EC940` 重新收集 9 段范围 → `sub_2757F0` 重算每段 XXH3-128 → 与基准比对。
3. 写出：`code-patch-prepare` = 9 段地址范围(`sections[0..8] = 0x.. - 0x..`)；`code-patch-check` = 9 行 `hash[0]=.. hash[1]=..`；任一段不符追加 **`detect tiny code patch!`**。

> 用途：检测对 libtiny 自身代码段的运行期字节篡改(inline hook / patch / trampoline 写入)。逐段 128bit 哈希 + 加载期基准，绕过单点 CRC 易被定位的弱点；`.text` 任意一处被改即触发。
> 入口 `sub_3EB6C0` 整体 OLLVM 控制流平坦化(满 `br x8` 计算跳转,如 @`0x3ebdfc`/`0x3ebe54`,偏移 `0x1e0beb38`)，Hex-Rays 静态解不全，故算法靠 trace 实锤而非反编译。

---

## s6 专项:运行环境/执行底层完整性组(反 DBI 插桩 + 反模拟器)

`s6`(bitmap `*|0|0|*|0|0|0|0|0|*|0|-`,12 位)是一组**底层执行环境完整性**子检查。每位由一个 future 链节点(`sub_31F904`/`sub_323B88`/…)`(***(x19+slot))()` poll 一个独立检查叶子,结果映射为 `0`(干净)/`*`或`1`(命中)/`-`(未启用)。category 路径机制见上文(hook `sub_3ECF04` 读 ctx 路径段 = "s6")。

### 逐位来源(frida hook 链节点 + 三级解引用 poll 目标实测)
| 链节点 | poll 目标 | 检查内容 |
|---|---|---|
| (key3) | 0x435774 | /proc/self/task 线程枚举反插桩 → `"1"` |
| (key9) | — | 某函数序言字节 inline-hook 检查(`FD 7B BF A9` = `stp x29,x30,[sp,#-0x10]!` 标准序言) |
| `sub_31F904`(slot 3848) | **`sub_446800`** | **SMC/JIT 执行测试**(详见下) |
| `sub_323B88`(slot 3832) | **`sub_446B50`** | **mincore + pagemap 按需分页一致性** |

### ★ sub_446800 = 自修改代码 / I-cache 一致性 / 执行完整性探针(反 DBI)
检测「运行期写一条指令、立刻执行,结果对不对」,识别**动态二进制插桩(Frida/QBDI)/ SMC 不友好模拟器 / 执行被劫持**。

```c
sub_446800():  // cxa_guard 一次性(byte_74C978)
  off_74BEC0 = sub_43B4A0();          // 取一块 RWX 可执行槽
  v6=0; v7=32;
  do {
    if (v6==99) break;                // 最多 99 轮
    *off_74BEC0 = v7 | 0xD2800000;    // ★写入指令 movz x0, #(v7>>5)  即"返回 N"
    v9 = off_74BEC0();                // ★立刻执行刚写的代码,取返回值
    v7 += 32;
  } while (v6 == v9);                  // 99 次每次换 N,执行结果必须 == 写入值
  // 全对 → 正常;任何一次发散 → 解密报错串 + sub_3ECF04 写证据
```

**能抓到什么**:
- **Frida / QBDI 等 DBI**:翻译并缓存代码,对「运行期新写入的自修改代码」是盲区——执行旧翻译缓存或跟不进新代码 → 返回值对不上。
- **I-cache 不一致 / 模拟器**:写完代码未正确同步 I-cache、或模拟器 SMC 处理不当 → 执行旧指令,结果错。
- **代码页被 hook / 执行重定向** → 返回值发散。

**QBDI trace 实证(对 sub_446800 单独 replay)**:函数在 seq≈65677465 执行,2 次 cxa_guard 正常记录后,**从 seq 65677600 起一大片连续 `unavailable` 空洞** —— 正是 `sub_43B4A0` 取 RWX 缓冲 + 写 `movz` + **执行那块缓冲**的位置。即**SMC 执行段逃出了 QBDI 插桩视野**(新 mmap 的 RWX 代码原生执行,recorder 记不到)。这恰好实证其反 DBI 原理:插桩工具要么跟不进(空洞)、要么跟进后结果/时序异常被检出。它故意把校验逻辑放进**运行期生成的代码**里跑,使静态分析看不到、插桩难透明跟进。

### sub_446B50 = mincore + /proc/self/pagemap 按需分页一致性(反模拟器/反内存篡改)
```c
sub_446B50():  // cxa_guard 一次性(byte_74C988)
  v6 = mmap(NULL, sz, RW, MAP_PRIVATE|ANON);    // 匿名映射一页
  mincore(v6, sz, &resident);                   // 触碰前:应"未驻留"
  pread64(pagemap_fd, &ent, 8, 8*(v6/pgsz));    // 读 /proc/self/pagemap,查 present 位(bit63)
  *v6 = 0;                                       // 写一下触发缺页
  mincore(v6, sz, &resident);                   // 触碰后:应"已驻留"
  // demand-paging 行为是否正常 → 写 "0"(248)/"1"(249);munmap
```
验证内核 demand-paging / 页驻留语义是否正常——**模拟器、异常内存管理、被插桩的内存**会表现不一致。

**QBDI trace 实测(对 sub_446B50 单独 replay,1 万条指令小 trace)**:
- seq 8075:`mincore(addr=0x75fd5fe000, len=0x1000, vec)`(直接 svc nr=232 @so 0x446c70)→ **ret=0**,addr 即刚 mmap 的匿名页。
- seq 8083:`ldrb w8,[sp,#0x1c]` → **w8=1**,即 mincore 写回的驻留字节 = **1(触碰前该页已驻留)**。
- seq 8084 `cbz w8` 不跳 → 走 **LABEL_13「触碰前已驻留」分支**:**短路**——不再做 `pread64` pagemap、也不做第二次 mincore(故全 trace 仅 1 条 svc),直接解密结果串(248→"0")经 `sub_3ECF04` 写入。

> **正常真机**:刚 mmap 的匿名页是 demand-paging,触碰前 vec 应为 0(不驻留),写一下才驻留。
> **QBDI replay 环境**:mincore 报触碰前就已驻留(vec=1)——正是该检查要找的**异常内存行为**(页被预先 fault-in / 内存语义不一致)。于是它没走「正常 demand-paging:touch→再 mincore→'1'」那条,而是短路进「已驻留」分支。**实证 sub_446B50 在插桩/replay 环境下确实命中了按需分页异常**,与静态反编译逻辑完全吻合。

> s6 结果码字典(同 [[libtiny-detection-dispatch]] 解密常量):`248→"0"`(干净)、`249→"1"`(命中)、`"-"`(未启用)。s6 整体 = 验证「CPU 能写+执行码、内存按需分页、代码未被 hook」的运行环境完整性组,是该 SDK 最硬核的反 DBI/反模拟器一环。

---

## s7 专项:应用身份完整性组(反克隆 / 多开 / 重打包 / 同UID寄生)

`s7`(bitmap `0|0|0|0`,4 位,本轮全 0=干净)= 一组**应用身份**子检查。frida hook 链节点实测:`sub_31CCAC`(poll slot=4056)→ poll_target = **`sub_443B30`**,`ctx_cat=s7`(三者闭合)。

### 检查叶子 sub_443B30 = 包名比对 + 同UID包枚举
```c
sub_443B30():  // cxa_guard 一次性(byte_74C900)
  env    = sub_4B2F68();                     // JNIEnv(AttachCurrentThread)
  expect = sub_132A00(xmmword_747D60);       // 期望包名常量
  actual = sub_2BA4C8();                      // 本进程包名(xmmword_746C08)
  if (expect != actual) → 报 "package name: <actual>" 异常分支   // 防重打包/改包名
  else:
     uid  = getuid();
     list = sub_4C3454(env, uid);             // ≈ PackageManager.getPackagesForUid(uid)
     for pkg in list:                         // (*env+1368)GetArrayLength / (*env+1384)GetObjectArrayElement
       name = GetStringUTFChars(pkg);         // sub_4BB520
       sub_3ECF04("package name: " + name);   // ★逐个报告同UID下的包
       if (name == expect) v41=1;             // 与期望包名比对
       DeleteLocalRef(pkg);                   // (*env+184)
```
**检测**:① 本进程包名是否 == 期望 `com.xingin.xhs`(防重打包);② 枚举与本应用**同 UID** 的所有包,逐个比对——**多开/分身/VirtualApp** 会让多个包共享同 UID,**重打包**会改包名,**同UID寄生**应用也会暴露。

### QBDI trace 实测(对 sub_443B30 单独 replay,~40K 指令)
| 项 | 实测值 |
|---|---|
| `getuid` @ seq 398 | uid = `0x284f` = **10319**(普通 app UID) |
| 同UID包枚举(JNI) | 仅 **`com.xingin.xhs` 一个**(trace 内 `com.` 字符串无第二个包名) |
| 证据串构建 | `package name: com.xingin.xhs` 于 seq 37682–38383 **逐字符增量拼出**(Rust `String::push`),经 `sub_3ECF04` 写入 |
| 包名比对 | 匹配 → 干净(enum 703464591) |

> 实证**未被克隆/多开**的基线:该 UID 仅 1 个合法包且包名匹配 → s7 该位 = `"0"`。
> 检出条件:同 UID 出现 **2+ 个包**(双开/分身)或**包名不符**(重打包)→ 命中。
> s7 其余 3 位是同组其它身份子检查,本轮全 `"0"`(未产 evidence,需各自链节点定位)。

---

## t 专项:原始检测取证桶(反 Hook/反模拟器/反自动化的全文上报)

`t` 不是压缩位图,而是**原始取证桶**:派发器 `sub_42F2D4` 派发的 **19 个叶子检测器**直接把**完整证据全文**写进 `t`(category="t",hook_s6.js 实测 19 行均为 `[t / key]`)。s/d 是对这批结果的压缩再投影,`t` 是未压缩原文(故每条证据可长达几百字节)。本轮命中 8 个 key(7/10/12/15/21/24/26/27)。

### t 的本质
把检测到的**每一处 hook/patch 的现场**(被 hook 符号、hooker 地址、覆盖字节、maps 区段)、**时序指纹**、**输入事件特征**等**原始数据全文上报给服务端裁决**,而非本地下二值结论。已命中 8 项的检测器与语义见 [[libtiny-detection-dispatch]] 全表;以下深析两个之前未细究的:

### key 24 = sub_431324 → sub_431388:内存写入计时基准(反模拟器 + 反单步/DBI)
```c
sub_431388():  // cxa_guard 一次性(byte_74AA88)
  npages = 0x2800000 / 4096 = 10240;        // 共 40MB
  buf = mmap(0, 40MB, RW, MAP_PRIVATE|ANON);
  // SIMD 建"每页一个指针"的数组(buf + (i<<pageshift)),先 touch 预热
  t0 = CNTVCT_EL0;                           // ★虚拟周期计数器
  for (r=0; r<100; r++)                      // ★100 轮
     for each page: *page_ptr = 0;           // 每轮向 10240 个页各写 1 字节(打散写)
  cycles = CNTVCT_EL0 - t0;                  // ★测周期
  munmap(buf);
  报 "%lf %lld %lld" = (cycles/100, 预热cycles, cycles) → sub_3ECF04
```
跨 10240 页 ×100 轮的**打散内存写**计 `CNTVCT_EL0` 周期 = **内存时序/性能指纹**。**模拟器(QEMU 翻译执行)**打散写走软件 MMU,周期暴涨;**单步/DBI 插桩**逐指令拦截,时序同样膨胀。不判布尔,**上报原始周期**(如 `59.938178 508036 8476`),服务端按真机阈值判模拟器/插桩。

### key 21 = sub_431810:输入事件(MotionEvent)监听枚举(反自动化/注入/Bot)
```c
sub_431810():  // 状态机门控 dword_6F0048==703464591
  if (!sub_450448())  报 "install listener failed!";  // 监听器是否已安装
  records = sub_450548();                    // 取监听到的事件记录(链表)
  env = sub_4B2F68();                         // JNIEnv
  for rec in records:                         // 逐条枚举,按 hash 去重(哈希表 xmmword_74AAB0)
     JNI 解析 rec → 类/方法名(GetStringUTFChars vtable+1352)
     拼成 "%s [%s] %s"  → sub_3ECF04 上报
```
证据 `[4098] [TOOL_TYPE_FINGER(1)] [0]`:`TOOL_TYPE_FINGER` 是 Android **MotionEvent** 工具类型常量,`4098`=事件 action —— 捕获的是**触摸输入事件**。SDK 自装一个输入监听器,枚举捕获到的 MotionEvent(action/tool_type/指针),识别:**自动化/脚本/Bot**(无真实手指、合成事件 tool_type 异常如 UNKNOWN=0)、**输入注入框架**(伪造点击滑动);监听器装不上(`install listener failed!`)本身也是异常信号。

| key | 函数 | 类型 | 判定方 |
|---|---|---|---|
| 24 | sub_431388 | 内存写入计时基准 | 反模拟器/反单步,上报原始周期,服务端判 |
| 21 | sub_431810 | 输入事件(MotionEvent)监听枚举 | 反自动化/注入/Bot,上报触摸事件特征 |

============================================== 3 ============================================

============================================== 4 ============================================

## json 来源

```
────────── [#50] detect-timing(各项耗时)  177B ──────────
  调用方(returnAddress) = libtiny.so+0x30e614   RVA=0x30e614
  lr @onEnter           = libtiny.so+0x30e614
  lr @onLeave(不可靠)   = 0x7491ffd10c
  ---- 完整 JSON ----
{"10":"1","11":"0","12":"1","14":"0","15":"0","16":"0","17":"0","18":"0","19":"0","20":"0","21":"0","24":"73.271589","26":"0","27":"1","29":"0","3":"0","30":"0","7":"0","8":"0"}
```

## key → 检测函数 完整表(19 项,frida [DISPATCH] 实测 + IDA)

`detect-timing` 的 19 个 key = `sub_42F2D4` 派发的 19 个叶子检测器,key↔函数已 frida hook 实测钉死:

| key | bit | 函数 | 检测内容 |
|----|----|------|---------|
| 3 | 0 | `0x435774` | /proc/self/task 线程枚举反插桩 |
| 7 | 1 | `0x435380` | fs/exec 类 libc 函数(`__open_2`/`execve`…)inline-hook 完整性 |
| 8 | 2 | `0x434fac` | `__system_property_*` inline-hook |
| 10 | 3 | `0x434d10` | ART/libart inline-hook 扫描(`art::gc::Heap*`/`ThreadList`) |
| 11 | 4 | `0x434988` | libc(`sched_yield`)maps hook |
| 12 | 5 | `0x4346e0` | linker64 hook(`__dl___loader_android_dlopen_ext`) |
| 14 | 6 | `0x433b94` | ART 运行时符号 inline-hook 扫描 |
| 15 | 7 | `0x433894` | 函数被改 `ret`(`C0 03 5F D6`) |
| 16 | 8 | `0x4337c4` | 反射 ActivityManager/Intent 被 hook 探针 |
| 17 | 9 | `0x433510` | `uname.release` 内核签名(模拟器) |
| 18 | 10 | `0x433460` | `java/util/Map` 方法ID hook |
| 19 | 11 | `0x432d5c` `det_mediadrm_property_fp` | **`AMediaDrm_getPropertyString` inline-hook(sub_41FF70 校验序言,防 DRM 设备ID 伪造)** |
| 20 | 12 | `0x432ab4` | `/lib64/libmediandk.so` 映射标记 |
| 21 | 13 | `0x431810` | MotionEvent 输入监听枚举(反自动化/Bot) |
| 24 | 14 | `0x431324`→`sub_431388` | 内存写入计时基准(反模拟器/反单步) |
| 26 | 15 | `0x430a28` | `/data/data/<pkg>` 可访问性扫描 |
| 27 | 16 | `0x4306f0` | shadowhook 检测(maps anon 区) |
| 29 | 17 | `0x430394` | JNI Java 层查询 |
| 30 | 18 | `0x42f654` | root su 路径扫描(直接 SVC,174 条黑名单) |

> 全在 `0x42xxxx–0x435xxx` 一簇,按 bit/key 倒序排列;另有 key 0=global 完整性、key 4=包名核对、key 9=函数序言字节(非派发叶子,内联跑)。

## detect-timing = 环境风控逐项结论(`{数字key→值}`)+ 异步 await 管线

### 它是什么检测
19 个派发检测器各自结果(`0`未中 / `1`命中,key24=计时原始值)。是 `sub_42F2D4` 派发器**直接产出的数字key结果 map**(s/d 重分组前的原始态)。**本质 = 「设备/运行环境是否被篡改」的风控指纹**:反 inline-hook(ART/libc/linker64/bytehook/shadowhook)、反调试/DBI、反模拟器、反 root/框架、反自动化/克隆 共 19 探针的命中压成 `{key→值}` 上报,服务端判设备是否被 hook/调试/伪造(反作弊/反爬/风控)。
> 本轮 `key10=1`(ART 被 inline-hook)、`key12=1`(linker64 被 hook)、`key27=1`(shadowhook 存在)→ 准确检出该研究机的插桩框架;`key24=73.27`=内存写入计时;其余 0=未检出。key↔检测器全表见 [[libtiny-detection-dispatch]]。

### 上报管线:异步 future + await(超时)+ 序列化(0x30E524 实证)
检测结果存在**异步 future 对象**(`byte_7494D0` 等),上报线程用 **`sub_30E190`(带超时 future-await 轮询 + 序列化)** await 就绪后序列化。QBDI trace(replay `0x30E524`)实证:

```asm
; 0x30E524 = 对结果对象发起 await 的调用壳
30e548  x0 = byte_7494D0          ; ★detect-timing 结果对象
30e558  x1 = unk_749440           ; 配套 future/锁
30e568  fmov s0, #2.0             ; ★timeout = 2.0
30e56c  blr sub_30E190
; sub_30E190 内:  fmul s0,#20 → fcvtzs w11 = 40 = 最大轮询轮数
;   每轮: 锁mutex → 查 future 状态 → 未就绪 nanosleep 退避重试 → 就绪则递归序列化
```
- `sub_30E190` = 带超时 future-await(`timeout×20=轮询上限`,2.0→**最多 40 轮**,`nanosleep` 退避)+ 就绪后递归序列化。
- `0x30E524` 专 await `byte_7494D0`(→detect-timing);emit 返回点 `0x30e614` 只是序列化递归里的深层返回,非关键节点。`0x30e4a4`/`0x30e750` 为其它结果对象(detect-bitmap/detect-detail)的 await/序列化点。

---

## 全上报管线追踪(cap ↔ emit 函数 ↔ 内容,4 层)

每个 cap 文件名尾号 = serde 序列化的 emit 返回地址。全链路 = **采集 → 注册 → 签名封装 → 加密封装**:

| 层 | cap | emit 函数 | 内容 |
|---|---|---|---|
| **采集** | `devfp-lite_1e5dec` | `sub_1E5BD0` | 设备指纹 x-fields(90+ 项:系统属性/内核/存储/时间戳/SIM…,见 section 1) |
| | `pkg_*` | `sub_2697E4`(0x269fb0/0x26a938) | 标识符 x-fields(UUID/ANDROID_ID/序列号/签名摘要/x165 文件时间指纹,见 section 2) |
| | `detect-bitmap_30e4a4` | `sub_30E190` | s/d 压缩位图 `"0\|*\|-"` |
| | `detect-timing_30e614` | `sub_30E190`(await `byte_7494D0`) | `{数字key→值}` 检测结论(key24=计时) |
| | `detect-detail_30e750` | `sub_30E690` | 完整证据全文(hook 现场) |
| **注册** | `register-body_24a7d0` | `sub_24A674` | `{appid,channel,did,gid,model,os_version,sdk_version}` 设备注册 |
| **签名封装** | `envelope-signed_1e9cac` | **`build_report_envelope_signed`** | `{a,c,k,p,s,t,u,v}` 会话身份信封 |
| **加密封装** | `envelope-enc_3002d8` | `sub_300108` | `{a,c,d,e,g,k,p,s,u,v,x}` 最终密文信封 |

### 签名封装 `build_report_envelope_signed`(0x1e9b30)
触发链:`a5b.p.intercept`(OkHttp 签名拦截器)→ `com.xingin.tiny.internal.t.a`(JNI)→ 本函数。栈上建 serde Map,逐字段 insert → `json_ser_new` 序列化 → `sub_4555C8` 对明文算签名/摘要。7 字段:
- `a` = appid `"ECFAAF01"`(常量)
- `c` = u64 单调递增请求 nonce(`*off_6D86C8` 每调 +1,**唯一每请求变的值**)
- `k` = `bytes_to_hex_string(g_session_key_32, 32)` → 64hex,**会话静态密钥**
- `s` = `bytes_to_hex_string(g_session_sig_64, 64)` → 128hex,**会话静态签名**
- `p`=`"a"`、`u`=did(40hex)、`v`=`"2.9.74"`(SDK 版本)
- `t` = 检测结果摘要 `{c,d,f,s,t,tt}`(`s:4098`=输入事件 action)
> 实测:`s/k/u` 整会话不变,仅 `c` 递增 ⇒ 这是**会话身份信封**,非每请求 HMAC。`s/k` 真值由 `session_key_derive_1/2` 派生写入全局,本函数只读+hex。

### 加密封装 `sub_300108`(0x3002d8)
`json_ser_new` 序列化信封 → `sub_1A0D0C(...)`(AES 加密)→ 产出密文 `"d"` 字段。最终 `envelope-enc` 结构:
- `d` = **AES 加密后的载荷**(`"y-WZYhe9Ym672QH2jrpVSQ"` base64url)
- `e` = `{device_id, sid(session), tt(ECDSA 签名 `MEUCIQ...`), uid, now, kk, cc, dd, rr, vv}`
- `a`=appid、`g`=gid(28B 摘要)、`k`/`s`=会话密钥/签名、`u`=did、`v`=版本、`x`=2

### 管线全景
```
检测(异步 future)──┐
  s/d/t/global       ├─► sub_30E190 await(超时40轮)+序列化 → detect-{bitmap,timing,detail}
设备指纹采集 ────────┤                                            │
  devfp(sub_1E5BD0)  │   pkg(sub_2697E4)                          │
  ───────────────────┴────────────────┬───────────────────────────┘
                                       ▼
              register-body(sub_24A674) 设备注册
                                       ▼
        build_report_envelope_signed: serde Map → json_ser_new → sub_4555C8 签名
          {a,c(nonce),k(会话密钥),s(会话签名),t(检测摘要),u(did),v}
                                       ▼
        sub_300108: json_ser_new → sub_1A0D0C(AES 加密) → d 密文
          {a,c,d(密文),e(session/ECDSA/device_id),g,k,p,s,u,v,x}
                                       ▼
                          OkHttp 拦截器 → HTTPS 上报
```
**结论**:libtiny 把「设备指纹(x-fields)+ 环境风控检测(s/d/t)」采集后,经 serde 序列化 → 会话密钥签名(`build_report_envelope_signed`)→ AES 加密(`sub_300108`)封成密文信封,由 OkHttp 签名拦截器随每个请求上报。`c` 是每请求递增 nonce,`k/s` 是会话级身份密钥/签名,`d` 是加密正文。



============================================== 3 ============================================


============================================== 4 ============================================
## json 来源

```
{"x0":"com.xingin.xhs","x1":"9.32.0","x10":"Redmi/gold/gold:13/TP1A.220624.014/V14.0.11.0.TNQCNXM:user/release-keys","x100":"1","x102":"1","x103":"android reference-ril 1.0","x104":"0000000000000000000000000000000000000000000000000000000000000000","x11":"pangu-build-component-system-298128-6hhzx-3734k-6w6nd","x110":"7560262d-e059-441f-aee8-e1590bfc579","x111":"0x337d4cd685007ba5f6bb0d1f6c496bf85f52c4cfc4fd98da368a53cb","x112":["192.168.50.1"],"x113":false,"x114":120.00000762939453,"x115":"2.9.74","x118":"running","x12":"TP1A.220624.014","x120":"0","x122":"1","x123":"Dalvik/2.1.0 (Linux; U; Android 13; 2312DRAABC Build/TP1A.220624.014)","x125":2708138710,"x126":["/apex/com.android.adservices/javalib/framework-adservices.jar","/apex/com.android.adservices/javalib/framework-sdksandbox.jar","/apex/com.android.appsearch/javalib/framework-appsearch.jar","/apex/com.android.art/javalib/bouncycastle.jar","/apex/com.android.art/javalib/core-libart.jar","/apex/com.android.art/javalib/core-oj.jar","/apex/com.android.art/javalib/okhttp.jar","/apex/com.android.btservices/javalib/framework-bluetooth.jar","/apex/com.android.conscrypt/javalib/conscrypt.jar","/apex/com.android.i18n/javalib/core-icu4j.jar","/apex/com.android.ipsec/javalib/android.net.ipsec.ike.jar","/apex/com.android.media/javalib/updatable-media.jar","/apex/com.android.mediaprovider/javalib/framework-mediaprovider.jar","/apex/com.android.ondevicepersonalization/javalib/framework-ondevicepersonalization.jar","/apex/com.android.os.statsd/javalib/framework-statsd.jar","/apex/com.android.permission/javalib/framework-permission-s.jar","/apex/com.android.permission/javalib/framework-permission.jar","/apex/com.android.scheduling/javalib/framework-scheduling.jar","/apex/com.android.sdkext/javalib/framework-sdkextensions.jar","/apex/com.android.tethering/javalib/framework-connectivity-t.jar","/apex/com.android.tethering/javalib/framework-connectivity.jar","/apex/com.android.tethering/javalib/framework-tethering.jar","/apex/com.android.uwb/javalib/framework-uwb.jar","/apex/com.android.wifi/javalib/framework-wifi.jar","/data/app/~~9NJNOADHLIr1VH97okgjSw==/com.xingin.xhs-K7TakgAuaEZrLAF52M1Btg==/base.apk","/data/app/~~9NJNOADHLIr1VH97okgjSw==/com.xingin.xhs-K7TakgAuaEZrLAF52M1Btg==/base.apk!classes10.dex","/data/app/~~9NJNOADHLIr1VH97okgjSw==/com.xingin.xhs-K7TakgAuaEZrLAF52M1Btg==/base.apk!classes11.dex","/data/app/~~9NJNOADHLIr1VH97okgjSw==/com.xingin.xhs-K7TakgAuaEZrLAF52M1Btg==/base.apk!classes12.dex","/data/app/~~9NJNOADHLIr1VH97okgjSw==/com.xingin.xhs-K7TakgAuaEZrLAF52M1Btg==/base.apk!classes13.dex","/data/app/~~9NJNOADHLIr1VH97okgjSw==/com.xingin.xhs-K7TakgAuaEZrLAF52M1Btg==/base.apk!classes14.dex","/data/app/~~9NJNOADHLIr1VH97okgjSw==/com.xingin.xhs-K7TakgAuaEZrLAF52M1Btg==/base.apk!classes15.dex","/data/app/~~9NJNOADHLIr1VH97okgjSw==/com.xingin.xhs-K7TakgAuaEZrLAF52M1Btg==/base.apk!classes16.dex","/data/app/~~9NJNOADHLIr1VH97okgjSw==/com.xingin.xhs-K7TakgAuaEZrLAF52M1Btg==/base.apk!classes17.dex","/data/app/~~9NJNOADHLIr1VH97okgjSw==/com.xingin.xhs-K7TakgAuaEZrLAF52M1Btg==/base.apk!classes18.dex","/data/app/~~9NJNOADHLIr1VH97okgjSw==/com.xingin.xhs-K7TakgAuaEZrLAF52M1Btg==/base.apk!classes19.dex","/data/app/~~9NJNOADHLIr1VH97okgjSw==/com.xingin.xhs-K7TakgAuaEZrLAF52M1Btg==/base.apk!classes2.dex","/data/app/~~9NJNOADHLIr1VH97okgjSw==/com.xingin.xhs-K7TakgAuaEZrLAF52M1Btg==/base.apk!classes3.dex","/data/app/~~9NJNOADHLIr1VH97okgjSw==/com.xingin.xhs-K7TakgAuaEZrLAF52M1Btg==/base.apk!classes4.dex","/data/app/~~9NJNOADHLIr1VH97okgjSw==/com.xingin.xhs-K7TakgAuaEZrLAF52M1Btg==/base.apk!classes5.dex","/data/app/~~9NJNOADHLIr1VH97okgjSw==/com.xingin.xhs-K7TakgAuaEZrLAF52M1Btg==/base.apk!classes6.dex","/data/app/~~9NJNOADHLIr1VH97okgjSw==/com.xingin.xhs-K7TakgAuaEZrLAF52M1Btg==/base.apk!classes7.dex","/data/app/~~9NJNOADHLIr1VH97okgjSw==/com.xingin.xhs-K7TakgAuaEZrLAF52M1Btg==/base.apk!classes8.dex","/data/app/~~9NJNOADHLIr1VH97okgjSw==/com.xingin.xhs-K7TakgAuaEZrLAF52M1Btg==/base.apk!classes9.dex","/data/app/~~Z15quS0UHnDai5mL08W9sQ==/com.google.android.gms-ULz53lL6jumIyCblD3klag==/base.apk","/data/app/~~Z15quS0UHnDai5mL08W9sQ==/com.google.android.gms-ULz53lL6jumIyCblD3klag==/base.apk!classes17.dex","/data/app/~~Z15quS0UHnDai5mL08W9sQ==/com.google.android.gms-ULz53lL6jumIyCblD3klag==/base.apk!classes2.dex","/data/app/~~Z15quS0UHnDai5mL08W9sQ==/com.google.android.gms-ULz53lL6jumIyCblD3klag==/split_AdsDynamite_installtime.apk","/data/app/~~Z15quS0UHnDai5mL08W9sQ==/com.google.android.gms-ULz53lL6jumIyCblD3klag==/split_DynamiteLoader_installtime.apk!classes2.dex","/data/app/~~Z15quS0UHnDai5mL08W9sQ==/com.google.android.gms-ULz53lL6jumIyCblD3klag==/split_DynamiteLoader_installtime.apk!classes3.dex","/data/app/~~Z15quS0UHnDai5mL08W9sQ==/com.google.android.gms-ULz53lL6jumIyCblD3klag==/split_MeasurementDynamite_installtime.apk!classes2.dex","/data/app/~~Z15quS0UHnDai5mL08W9sQ==/com.google.android.gms-ULz53lL6jumIyCblD3klag==/split_MeasurementDynamite_installtime.apk!classes3.dex","/data/user/0/com.xingin.xhs/Anonymous-DexFile@1223465333.jar","/data/user/0/com.xingin.xhs/Anonymous-DexFile@2331305250.jar","/data/user/0/com.xingin.xhs/Anonymous-DexFile@3773095269.jar","/data/user/0/com.xingin.xhs/Anonymous-DexFile@78738837.jar","/data/user/0/com.xingin.xhs/app_cache/c4d121c215evx1s51d.dex","/system/framework/MiuiBooster.jar","/system/framework/ext.jar","/system/framework/framework-graphics.jar","/system/framework/framework.jar","/system/framework/framework.jar!classes2.dex","/system/framework/framework.jar!classes3.dex","/system/framework/framework.jar!classes4.dex","/system/framework/ims-common.jar","/system/framework/mediatek-carrier-config-manager.jar","/system/framework/mediatek-common.jar","/system/framework/mediatek-framework.jar","/system/framework/mediatek-ims-base.jar","/system/framework/mediatek-ims-common.jar","/system/framework/mediatek-telecom-common.jar","/system/framework/mediatek-telephony-base.jar","/system/framework/mediatek-telephony-common.jar","/system/framework/telephony-common.jar","/system/framework/voip-common.jar","/system_ext/app/CatcherPatch/CatcherPatch.apk","/system_ext/app/MiuiContentCatcher/MiuiContentCatcher.apk","/system_ext/framework/miui-framework.jar"],"x127":".","x128":"","x13":"release-keys","x131":"0","x134":"157f29b9-a1ce-4a1b-b8d9-d605bd0471f4","x135":{"1":"D0A6434F1A804AA847205FCC7577C4CB","7":"1CB30AAA8213C8A4F92B6C3A1BB52B85"},"x136":"1","x137":"65BF9BDF57DAF122EA47643868A699F2","x138":"48283626DEF7994D8F6DA7CC16A5DFE5","x14":"user","x143":"F82EECD866FDC5768D900B45BCB9AA70","x144":["Android/gsi_arm64/generic_arm64:12/SGR1.240108.001.C2/12455537:user/release-keys","Redmi/gold/gold:13/TP1A.220624.014/V14.0.11.0.TNQCNXM:user/release-keys","Xiaomi/miproduct_gold_cn/missi:13/TP1A.220624.014/V14.0.11.0.TNQCNXM:user/release-keys","Xiaomi/missi/missi:13/TP1A.220624.014/V14.0.11.0.TNQCNXM:user/release-keys","Xiaomi/missi/missi:13/TP1A.220624.014/V14.0.11.0.TNQCNXM:user/release-keys","Redmi/gold/gold:13/TP1A.220624.014/V14.0.11.0.TNQCNXM:user/release-keys"],"x145":{"com.xingin.xhs":"7c810529b83254b2d1e25cb4930bb23d49688f3947359f0377c74186"},"x146":"7c810529b83254b2d1e25cb4930bb23d49688f3947359f0377c74186","x15":"V14.0.11.0.TNQCNXM","x155":"NA349W005842                                                111","x16":"13","x165":{"1":"1782115429312001002-134-64802-0000fd2200000000-4076150800","10":"1782115638708001015-2043711-19-0000000000000000-16914836","11":"1782115634952001014-2025087-19-0000000000000000-16914836","12":"1230768000000000000-229-64769-0000000000000000-1702057286","2":"1782115631400001014-1-1048737-0000000000000000-16914836","4":"1781883842496000005-3989-64802-0000fd2200000000-4076150800","6":"1782098687468000004-7438-64802-0000fd2200000000-4076150800","7":"1782098637516000001-257-17-0000000000000000-16914836","9":"1782098611432000000-134-17-0000000000000000-16914836"},"x17":33,"x170":"id_provider","x171":"aa3c9779598403b9","x173":"bf2949218a376f5b","x174":"1eed1c17-6eed-4f6b-bd83-34f538ab3129","x18":"2026-06-05","x180":"6aa84e97-cd87-449f-9cf6-407155b12497","x185":"IiGgSsKkCVvEePcp","x186":1782115638861,"x187":1782115636387,"x189":"1781883842496000005-3989-64802-0000fd2200000000-4076150800","x19":"gold","x193":{"1":""},"x194":"1","x198":{"com.xingin.xhs.index.v2.IndexActivityV2":["com.miui.home"]},"x2":9320802,"x20":"Redmi","x202":"1","x203":"1","x205":{"x3":"785E181CDDA8DEDD8851F4ED140995F0281FCB07"},"x206":0,"x207":0,"x208":{"c":0,"d":0,"f":0,"s":4098,"t":0,"tt":[]},"x209":"miui","x21":"arm64-v8a,armeabi-v7a,armeabi","x210":"V14.0.11.0.TNQCNXM","x214":"green","x22":"gold","x220":"locked","x227":["CN=DigiCert Global Root G2, OU=www.digicert.com, O=DigiCert Inc, C=US","CN=DNSPod TLS RSA CA 2025, O=\"DNSPod, Inc.\", C=CN","CN=*.xiaohongshu.com, O=行吟信息科技（上海）有限公司, ST=上海市, C=CN","unknown"],"x228":[],"x23":"Xiaomi","x230":[{"a":true,"d":"a718a782d34bc767f4689c232d64d527998ea7fd","e":false,"k":2,"n":"Virtual","pi":0,"s":"0x301","v":true,"vi":0},{"a":true,"d":"8136f1e77728f603ac0ec0e545d338eba3cbcbc0","e":true,"k":1,"n":"uinput-goodix","pi":2184,"s":"0x501","v":false,"vi":1638},{"a":true,"d":"9a244e01c90550ca2eb2798ffe20d8731e811765","e":false,"k":1,"n":"mtk-kpd","pi":0,"s":"0x101","v":false,"vi":0},{"a":true,"d":"485d69228e24f5e46da1598745890b214130dbc4","e":false,"k":1,"n":"mtk-pmic-keys","pi":1,"s":"0x101","v":false,"vi":1},{"a":true,"d":"c63c3be2de98f10e6bbd97f78684d819a6c862b9","e":false,"k":1,"n":"goodix_ts","pi":1,"s":"0x1103","v":false,"vi":10182},{"a":true,"d":"393bc96fab9421f9d6a6059cfe79e8b042c8755d","e":false,"k":1,"n":"mt6833-mt6359 Headset Jack","pi":0,"s":"0x80000101","v":false,"vi":0},{"a":true,"d":"b694711109f0e5ef59f2ca6f8166f03a196c6741","e":false,"k":1,"n":"swtp","pi":0,"s":"0x101","v":false,"vi":0}],"x231":115014074368,"x232":115014074368,"x234":{"1":1715582874664,"2":1715582851796,"3":1715582851672},"x235":4966300,"x236":50246578176,"x237":50246578176,"x238":"cn","x239":true,"x24":"2312DRAABC","x241":{"1":"BB07601C5B64ABD7252C189A6696FB53","10":"B905926472AA5377AA50FBFC5D72EA4D","11":"3AF65525F7CAEDAF2F94C45BD4F033AE","12":"C81FE23F84F8451DEB9D5CFC0B0EA679","2":"E9FD1287415BDB0C7CE7D6B510939F5C","3":"89B6704C169054418BD65E13F86B863A","4":"35FF6850B966C8F1A0FFD39EACDEE99B","5":"5F612E830089EE4859ADF3ADCE72294A","6":"2455AD45F0879DE10F50619B497AA0F5","7":"A167F360CA8D112B347CF90B79A5824D","8":"A3800D378E963A50F47E64C1BF161037","9":"90DD3AF1D10CBF84CDFF9920A2BD4869"},"x242":[],"x243":1782115634938,"x244":0,"x247":{"0":72.72727272727273,"1":46.666666666666664,"2":47.05882352941177,"3":0.0,"4":80.0,"5":47.05882352941177},"x248":"{\"BOARD\":\"gold\",\"SOC_MANUFACTURER\":\"Mediatek\",\"IS_MIUI\":true,\"CPU_ABI2\":\"\",\"IS_TIMINGTRACE\":false,\"HOST\":\"pangu-build-component-system-298128-6hhzx-3734k-6w6nd\",\"IS_TREBLE_ENABLED\":true,\"SUPPORTED_64_BIT_ABIS\":[\"arm64-v8a\"],\"CPU_ABI\":\"arm64-v8a\",\"PERMISSIONS_REVIEW_REQUIRED\":true,\"IS_USERDEBUG\":false,\"DISPLAY\":\"TP1A.220624.014\",\"HW_TIMEOUT_MULTIPLIER\":1,\"IS_ARC\":false,\"SUPPORTED_ABIS\":[\"arm64-v8a\",\"armeabi-v7a\",\"armeabi\"],\"FINGERPRINT\":\"Redmi/gold/gold:13/TP1A.220624.014/V14.0.11.0.TNQCNXM:user/release-keys\",\"PRODUCT\":\"gold\",\"ID\":\"TP1A.220624.014\",\"SOC_MODEL\":\"MT6833V/PNZA\",\"TYPE\":\"user\",\"SERIAL\":\"unknown\",\"Partition\":{\"PARTITION_NAME_OEM\":\"oem\",\"PARTITION_NAME_ODM\":\"odm\",\"PARTITION_NAME_SYSTEM\":\"system\",\"PARTITION_NAME_PRODUCT\":\"product\",\"PARTITION_NAME_SYSTEM_EXT\":\"system_ext\",\"PARTITION_NAME_VENDOR\":\"vendor\",\"PARTITION_NAME_BOOTIMAGE\":\"bootimage\"},\"IS_ENG\":false,\"DEVICE\":\"gold\",\"ODM_SKU\":\"gold_cn\",\"TIME\":1715582733000,\"IS_USER\":true,\"MODEL\":\"2312DRAABC\",\"MANUFACTURER\":\"Xiaomi\",\"USER\":\"builder\",\"BRAND\":\"Redmi\",\"VERSION_CODES\":{\"LOLLIPOP_MR1\":22,\"CUPCAKE\":3,\"JELLY_BEAN_MR1\":17,\"JELLY_BEAN_MR2\":18,\"JELLY_BEAN\":16,\"L\":21,\"N_MR1\":25,\"M\":23,\"TIRAMISU\":33,\"N\":24,\"BASE\":1,\"O\":26,\"P\":28,\"Q\":29,\"R\":30,\"S\":31,\"HONEYCOMB_MR2\":13,\"HONEYCOMB_MR1\":12,\"FROYO\":8,\"ECLAIR_0_1\":6,\"KITKAT_WATCH\":20,\"CUR_DEVELOPMENT\":10000,\"DONUT\":4,\"GINGERBREAD_MR1\":10,\"BASE_1_1\":2,\"ICE_CREAM_SANDWICH_MR1\":15,\"LOLLIPOP\":21,\"ECLAIR_MR1\":7,\"ECLAIR\":5,\"KITKAT\":19,\"S_V2\":32,\"O_MR1\":27,\"HONEYCOMB\":11,\"ICE_CREAM_SANDWICH\":14,\"GINGERBREAD\":9},\"SUPPORTED_32_BIT_ABIS\":[\"armeabi-v7a\",\"armeabi\"],\"HARDWARE\":\"mt6833\",\"IS_DEBUGGABLE\":false,\"BOOTLOADER\":\"unknown\",\"VERSION\":{\"ALL_CODENAMES\":[\"REL\"],\"ACTIVE_CODENAMES\":[],\"MIN_SUPPORTED_TARGET_SDK_INT\":23,\"RESOURCES_SDK_INT\":33,\"SECURITY_PATCH\":\"2026-06-05\",\"BASE_OS\":\"\",\"RELEASE\":\"13\",\"MEDIA_PERFORMANCE_CLASS\":0,\"CODENAME\":\"REL\",\"RELEASE_OR_CODENAME\":\"13\",\"RELEASE_OR_PREVIEW_DISPLAY\":\"13\",\"KNOWN_CODENAMES\":[\"HoneycombMr1\",\"HoneycombMr2\",\"Lollipop\",\"Kitkat\",\"Tiramisu\",\"Gingerbread\",\"Cupcake\",\"IceCreamSandwichMr1\",\"JellyBean\",\"IceCreamSandwich\",\"LollipopMr1\",\"M\",\"N\",\"O\",\"P\",\"Q\",\"R\",\"S\",\"Sv2\",\"Base\",\"NMr1\",\"OMr1\",\"JellyBeanMr1\",\"JellyBeanMr2\",\"Donut\",\"Froyo\",\"GingerbreadMr1\",\"EclairMr1\",\"Honeycomb\",\"Eclair01\",\"KitkatWatch\",\"Base11\",\"Eclair\"],\"SDK_INT\":33,\"PREVIEW_SDK_FINGERPRINT\":\"REL\",\"DEVICE_INITIAL_SDK_INT\":33,\"PREVIEW_SDK_INT\":0,\"SDK\":\"33\",\"INCREMENTAL\":\"V14.0.11.0.TNQCNXM\"},\"RADIO\":\"unknown\",\"TAG\":\"Build\",\"UNKNOWN\":\"unknown\",\"IS_EMULATOR\":false,\"SKU\":\"unknown\",\"TAGS\":\"release-keys\"}","x249":"com.xingin.xhs","x25":"gold","x251":"instrumentation:com.dragon.read/com.bytedance.common.component.CommonInstrumentation (target=com.dragon.read)\ninstrumentation:com.eg.android.AlipayGphone/com.alipay.mobile.clean.CleanInstrumentation (target=com.eg.android.AlipayGphone)\ninstrumentation:com.eg.android.AlipayGphone/com.alipay.mobile.quinox.preload.PreloadInstrumentation (target=com.eg.android.AlipayGphone)\ninstrumentation:com.eg.android.AlipayGphone/com.alipay.stability.action.process.ActionInstrumentation (target=com.eg.android.AlipayGphone)\ninstrumentation:com.ss.android.article.news/com.bytedance.common.component.CommonInstrumentation (target=com.ss.android.article.news)\ninstrumentation:com.ss.android.ugc.aweme/com.bytedance.common.component.CommonInstrumentation (target=com.ss.android.ugc.aweme)\ninstrumentation:com.taobao.taobao/com.taobao.adaemon.TriggerInstrumentation (target=com.taobao.taobao)\ninstrumentation:com.xs.fm/com.bytedance.common.component.CommonInstrumentation (target=com.xs.fm)\n","x256":"Linux localhost 5.10.198-GKI-Yuri #1 SMP PREEMPT Sun Aug 17 16:15:20 UTC 2025 aarch64 Toybox\n","x258":1,"x259":1,"x26":"aarch64","x260":1782115646113,"x261":1,"x263":0,"x264":0,"x265":"50:29","x266":1782114445776,"x267":0,"x268":0,"x269":1230768000000,"x27":"5.10.198-GKI-Yuri","x272":0,"x273":"0","x274":{"a":25,"c":[{"k":"MIIFYDCCA0igAwIBAgIJAOj6GWMU0voYMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNVBAUTEGY5MjAwOWU4NTNiNmIwNDUwHhcNMTYwNTI2MTYyODUyWhcNMjYwNTI0MTYyODUyWjAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xUFmOr75gvMsd/dTEDDJdSSxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5jlRfdnJLmN0pTy/4lj4/7tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y//0rb+T+W8a9nsNL/ggjnar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73XpXyTqRxB/M0n1n/W9nGqC4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYImQQcHtGl/m00QLVWutHQoVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB+TxywElgS70vE0XmLD+OJtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7quvmag8jfPioyKvxnK/EgsTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgpZrt3i5MIlCaY504LzSRiigHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7gLiMm0jhO2B6tUXHI/+MRPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82ixPvZtXQpUpuL12ab+9EaDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/bkwSWc+NpUFgNPN9PvQi8WEg5UmAGMCAwEAAaOBpjCBozAdBgNVHQ4EFgQUNmHhAHyIBQlRi0RsR/8aTMnqTxIwHwYDVR0jBBgwFoAUNmHhAHyIBQlRi0RsR/8aTMnqTxIwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAYYwQAYDVR0fBDkwNzA1oDOgMYYvaHR0cHM6Ly9hbmRyb2lkLmdvb2dsZWFwaXMuY29tL2F0dGVzdGF0aW9uL2NybC8wDQYJKoZIhvcNAQELBQADggIBACDIw41L3KlXG0aMiS//cqrG+EShHUGo8HNsw30W1kJtjn6UBwRM6jnmiwfBPb8VA91chb2vssAtX2zbTvqBJ9+LBPGCdw/E53Rbf86qhxKaiAHOjpvAy5Y3m00mqC0w/Zwvju1twb4vhLaJ5NkUJYsUS7rmJKHHBnETLi8GFqiEsqTWpG/6ibYCv7rYDBJDcR9W62BW9jfIoBQcxUCUJouMPH25lLNcDc1ssqvC2v7iUgI9LeoM1sNovqPmQUiG9rHli1vXxzCyaMTjwftkJLkf6724DFhuKug2jITV0QkXvaJWF4nUaHOTNA4uJU9WDvZLI1j83A+/xnAJUucIv/zGJ1AMH2boHqF8CY16LpsYgBt6tKxxWH00XcyDCdW2KlBCeqbQPcsFmWyWugxdcekhYsAWyoSf818NUsZdBWBaR/OukXrNLfkQ79IyZohZbvabO/X+MVT3rriAoKc8oE2Uws6DF+60PV7/WIPjNvXySdqspImSN78mflxDqwLqRBYkA3I75qppLGG9rp7UCdRjxMl8ZDBld+7yvHVgt1cVzJx9xnyGCC23UaicMDSXYrB4I4WHXPGjxhZuCuPBLTdOLU8YRvMYdEvYebWHMpvwGCF6bAx3JBpIeOQ1wDB5y0USicV3YgYGmi+NZfhA4URSh77Yd6uuJOJENRaNVTzk"},{"k":"MIIFfzCCA2egAwIBAgIKA4gmZ2BliZaFzzANBgkqhkiG9w0BAQsFADAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MB4XDTE4MTIwMzIyNDQzOVoXDTI4MTEzMDIyNDQzOVowKTEZMBcGA1UEBRMQYjUyZGM5NzBjNGRmODJmMDEMMAoGA1UEDAwDVEVFMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEArNicdR8pXRfp46KEc0KeUqqM3cAOWn04/Sn9jPGXYH80PqgTPhRSQ9kjhd6qg+Sd2Cenx9vBePDDa2BKpPAA9X7RXB7Tqbn494m8GBCC0XCKMAzMq5N0zc8oJTz9BB5YCwJ0gIcoqCuaKL96DEVunjvnaAAljdJayvNjUjFNAf2ZhmJGUfQPlVasGSQxO6PbYCinNf/FZN0CN4Bd7xF2FyQLWfDBi/FLNhN468MZ9pGhkMmnkbqtthe8ujy8b//dkUkcNjhQxZZDeSdHp4hpLgJhC/vF3Sqi6z+eC5GBG4oxWWLqpRUhXXpItxWPxwhhAOErBDNurz1sO/KMK5+9KI3BYD8V6PRrK4+xjxJ04JHZz9IVMvnC4nCM+WezsOsCl2Qm9zY5/+61D0gwI/KjJPsd8TenCIv9ImXmA2s+OLWYGamVXzM0PCuwpDF0K94JWGixyfqTYTMEAB99SwaBmAIdSXalMr0hHijQjgZdYIHEMSP4qKhvPN/uXvi7MYZcoxaoHxeMjTwNuCzIHii9my9FtaT/DlFdh+OEBH/QLR16AF+yliOLOauj3kuKzL4B2HxpYVR5TF6QXBS+t+9krsdm3uvxgPBEc1StJZDqhnKQ0kdwUeXlDcq00mllKpB534J2GFiSLNtQB1Qtf7GUypzoVNFg0b4sX1kDh72KmnECAwEAAaOBtjCBszAdBgNVHQ4EFgQUqzG1Abtzml5uRR2z1IPcfQrxFxswHwYDVR0jBBgwFoAUNmHhAHyIBQlRi0RsR/8aTMnqTxIwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAgQwUAYDVR0fBEkwRzBFoEOgQYY/aHR0cHM6Ly9hbmRyb2lkLmdvb2dsZWFwaXMuY29tL2F0dGVzdGF0aW9uL2NybC9FOEZBMTk2MzE0RDJGQTE4MA0GCSqGSIb3DQEBCwUAA4ICAQCGQ2TF+xnZ4xykuNvSz4RlZ5nIggz5RTZJzxJA4ZYYoylIAGkYFy1c5y6mnX4bLfftILfqitgi4j/2W3seog1INRwI6tEgKsqFAzXz5dNHEz5Qbu8GRE2bzQajPZCjE1/EEze9TIGE9BsNlB/bHcK2w2kh0xToqqXYvMYsDEbZP/JBHinvvvxS2cDDtUvlbG5kREMohFmIJfa5AilDr8ifVAxu4aNcVsS2aHeHE/HRBjDH0+W1y9zYyDTzS2zclAmPhtWUSsuWfOPVA46KBux4XF4kG1WGgIugNOBuyJrun27mUJbfa/tod8mjAbWiMcoQaVuhKLulTssNXYAupHfe7/k6PCHt+6yHnyDPVB3znMcPp0tsZPpshTYHNYPBMUyYnKgasYH0iuNX3Uv2hTxsNIqEAD+SG42ALcA/1X8pYdeE56CwMDlo29561V/S9wQx5wCsxRDc0Q0tBGI9GcM5HiZGfy8Ue0nCH6uBzkLM7gDywZDH4unNEurcvqZZ5wiLtspekxQ+sPkFKdMLp2aVKDl+VsvXmB6M1e0Y6XmClF6iU8PqDRcYzAh+3NJolggXHJFLbgJOFRZ+tfI2OwnQAA7k2PhzFt3QviJN/J57Q1T/noBZF1Oml6dwjn3HPM8Z15flakgUUM0XbtKWYpQcDgrO3c9prrPVJ7yCggntHw=="},{"k":"MIIFETCCAvmgAwIBAgIKETmYYkmTKRdWljANBgkqhkiG9w0BAQsFADApMRkwFwYDVQQFExBiNTJkYzk3MGM0ZGY4MmYwMQwwCgYDVQQMDANURUUwHhcNMTgxMjAzMjI1NjE5WhcNMjgxMTMwMjI1NjE5WjApMRkwFwYDVQQFExBhOTZkZDg4Y2Y4MTY1M2Q5MQwwCgYDVQQMDANURUUwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQDUeYx/QCcQuDltQ+JW+1ygeykirIwlC08ms1rwxgMOUeehd0Av6nPLkFGBJW700u5dyyVCVGK4kqM1ot/uUMQUCa3XfO3HzYA2O1zEzCe0xnW4JW0fzGOJp0uahGOiDyIWA69j1jPkPr0OPt4xyLzCiP8ZdxthEjy1G2x7WaUqcvqZ2zU4x+DrrC0DKkbVrxfZ1ZWMFw+ehjIJdprvz5w+cn4nYhqymzP68UqgB6QM5Nsm3zqdx2jCRDTZCEcdm/ZcvqTgCzKL1mY3p3NQOh/qziH22QOpSfRITLQTIuJqJCbX/XGZe3aG1EONF86eLQtBArqOk4253TVIb2X+u0HTtCXFsZPJgZA8CCdnbdKhZ7Lb31c4nXH7VCwVfN8iZGqY4K/QAQ4DpGRDLfZI25vlw/hBvERp7h1h51RgAN+kIQYTT0M7nAhic+DsE0v0HQf7JX7oYpaBjLGOqXoW9Akdz7CpdaYrgn0Su060E80WUr70OP6/LPUH/s5MAiN9Ev0CAwEAAaOBujCBtzAdBgNVHQ4EFgQUIek5OG2+FardjPyApKAf2t7d8kAwHwYDVR0jBBgwFoAUqzG1Abtzml5uRR2z1IPcfQrxFxswDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAgQwVAYDVR0fBE0wSzBJoEegRYZDaHR0cHM6Ly9hbmRyb2lkLmdvb2dsZWFwaXMuY29tL2F0dGVzdGF0aW9uL2NybC8xMTM5OTg2MjQ5OTMyOTE3NTY5NjANBgkqhkiG9w0BAQsFAAOCAgEALhCZj8hLb9d3/20sWQQseCfF9PUreWeYwoTCs2b8kTxEWKResd/o8X3NUo4+hHgHw6JnFQGsgZncyxdx6lp73NJFj7WFNKX9tJ7KOQCGGI9ekiGwdqjwxfi82i8qPzjVxF0GrRAWIHQP8/p3KpWCW2ZHEXl/la3jbVvD+ahIr8ZOVE6RPS500E0O/FQg3sFydcTnlzsdvbzfrTopxtKkyKISjfqdHbEUY2MbTfVRAfRsa0CkklDEiDiY6lxFQGq21GQawXGjQH94xBAYgX9EXTMW/WvwuotuT1upbl1ZfaMXrdJEo/37ndPIaKSmc8oUVmcdGF5CxnLE7Z7jfcgKsR7mZ+KQNDsfAm1WnEAejnUoZPaqZ3GOTyk0hpgitz7JrXrGBj0z9bcZM3Al9FUvYX+DIN4qClb5dMjC98N/yN0gS1QP7W5tX/uqza6FOBZnhr5fLJrKGTmRLG7V/yUDCt3mtbu8A/eqE7LHI3auMDQtncI5k7Ym0tT1eBJmmI8xx99+eO3bfKfYrV4PoAt438tOff+s790o/VtLSiPEH25K2/croozwkAJxoMcGTCcezNO8Y8XWgeKRK4KNMzN69njhwzVsulArNfSJstN2s8UWB7NpfVPDVEpVCz1M7U5jKmUcN/jo20D75dmQKQJzGxQkuK8AgU3y7qdDbC2ITaE="},{"k":"MIID4DCCAkigAwIBAgIBATANBgkqhkiG9w0BAQsFADApMRkwFwYDVQQFExBhOTZkZDg4Y2Y4MTY1M2Q5MQwwCgYDVQQMDANURUUwHhcNMjYwNjIyMDQyNTM4WhcNNDgwMTAxMDAwMDAwWjAfMR0wGwYDVQQDExRBbmRyb2lkIEtleXN0b3JlIEtleTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABHhR4aFwAgX1zOnDVSmg/CBrBBq7Js0bas9VY9U33mtXmXBPFC6213bi5VIDQD8CXssaQdYZJ2LvIrpFnR+4EDWjggFmMIIBYjAOBgNVHQ8BAf8EBAMCB4AwggFOBgorBgEEAdZ5AgERBIIBPjCCAToCAWQKAQECAWQKAQEEMjE3ODIxMDIzMzY2MjJfMDRmNGU2NjItZDk2NS0zNGQ3LThlY2YtNGY1OTI4NjE2OTJiBAAwUr+FPQgCBgGe7ZOtQ7+FRUIEQDA+MRgwFgQOY29tLnhpbmdpbi54aHMCBACOOWIxIgQg2/Ld/mjcbD1729HHCq4TmT9Q+pm1HW8MZoooTunm/c0wgaGhBTEDAgECogMCAQOjBAICAQClBTEDAgEEqgMCAQG/g3cCBQC/hT4DAgEAv4VATDBKBCDF08cbxw1Y4+BAnKnZs0wNusHS8Jpd6UikuPCQ8ZJpZQEB/woBAAQgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC/hUEFAgMB+9C/hUIFAgMDF26/hU4GAgQBNSb9v4VPBgIEATUm/TANBgkqhkiG9w0BAQsFAAOCAYEAlTl8L14G1250sZjrNfwwjCLe+1fHjt+jP9jcJFLEJJfmCbaMbBWpcIn4CpPjI7JrwMSGo5jhdfCeEzaiiNCAIctjobY95MQg287AZuE82+TvWe4mWLojrLgE1MGRfXOH6ZtQfRdgjJ26takMzl8ESYWqJXANaWlOBwUXA0C3JAylbUwHBc3zx9MhRd8yGnGF+ACqKCj2n2PbYGoSnZxIgd2jTlnZPXg/S3BSe5MCQr/WSy1H8oWCT3mC0tofZ3E24MRjJUVcaUhkBvpYqZc11NxbwIvvAMYJLtiIhV9hgirev3c2QEneDds0gSIMPSjfspNypJ7poUduIdSlmAIw9bwRG1ZKwOHBJdZmW7PPgUKxeqjVkdo1CKS6vd5Qp6O0cFF8gMRqqIFZFqw47ZKuGrfwm9xBWDgxduPWgGzrRq2f6Wu46ajUjaRZeMCso9DhSGmtBEUE5SQ9k+7n3NUX+j9dnZHmCGSzjPdEhTNlU4cGkSxWvPOwxbpuoawd1tab"}],"f":1,"g":"1782102336622_04f4e662-d965-34d7-8ecf-4f592861692b","h":1,"v":0,"z":1},"x276":"4:memory:/\n3:cpuset:/top-app\n2:cpu:/top-app\n1:blkio:/\n0::/uid_10314/pid_28952","x277":0.0,"x278":"0xd0b","x279":"0x41","x28":"#1 SMP PREEMPT Sun Aug 17 16:15:20 UTC 2025","x280":"0x00000000412fd050","x281":"0x0000000000000000","x282":{"x1":1782115634970,"x3":1782115641163,"x4":1782115647126},"x283":13,"x284":16,"x285":0,"x286":"EAACAAgAAgDV0vfLbh43GtJ-jfyImNaOA6KzJAOWSftiCTRqDKx-GhpdgvZFgmlB","x287":[0,4,5],"x288":[0,1,2,3,4,5,6,7,8,9],"x289":1782115646119,"x29":"MOLY.NR15.R3.MP.V120.3.P48,MOLY.NR15.R3.MP.V120.3.P48","x290":1,"x291":0,"x293":2111929,"x294":"","x295":"EyUj3U8VOPpuzto6D5cuiM8LP4e04j3rO3GCA3VddWa5eDyFaT8YoWDyMeUEDmlfcH1t6N1gjqJxQq3x9HNdt+ugwAyQ8uFJaNIFnOqNiRHuq5i1sVewcuiq33my9rCfotDiEtXlqv/cC3R1yVpF1Q+RgLBVMQUfK2CzSRrQYxz7YWR0uOMXAPX8ltuDBUbmfaX4BpyPm7PUSbZY/mDhoM56KyYpMUGpsBvoihsvgJ/BZbrVn2MFDekbyWi5c5VKaOt9E7Vn0451OIaiio7zLnXO0YX6QQZjhicYoUmYd53jEM1baX3OAr3TdCWQk0IvKInzW4+qxBYtME3/ZZylUWxOEcFY1g+2naoV0+GnaZ36CtbSEE9Mku+WclR2otL6KA9wttST1u51+SJUxChd9K/GJUqRxCrOoFe+ruFLV6U0r/QMdgyAipsLS7cWo5M60HpdyecnA0yJJ+WlnBiawR//Yw7p+/UH7CyBuDqNLuONHSMG2TdaWwbw2jEGZzoB7AIKwqRhageF2AUKCCjxuc+tpq/fk/W0vbgLkPMMA58ApDG22f4p6vSmJO8vD4yXEurSzOh2b/0smc41UqhglTyA0NYctz48zANRRFgbmFVgqRPwds9MLNi2Dhe5/UlBhtNHmgCS4s+4vaF7rJOv2JAmvCZSDFGiiABZFu94orYIOEkeGbalquATxAgeNr5u2ol+z974mPEBHayj1d4Uv+Z86z+YuVfuqATOQLPRyd+316Cw8+wkHJJ7Flv3ulKfHbAuBjfZ77dMouanB1cwdRDmD+ZybrYbe5od5FZZa/CdBpkjabqaHlVYU75ulpEltfpUzVs2HxIvf4ZblzndB9NQd2Za82V59xjGrYdOaJebAeJXRhWksST954HbflQ/fbI7K37XLJNM1OWEiEKkcWZ60QR+0PTk8qmwrYtCGgxhL8y6eMn61/juc55tfYbUrMfj/pJX15KZJCPub+8mvEXisLHmL01OwhGB3z2NQ4wmE0D/B5/D0867XdFjJHfvUWfZa5lTVKdmPqfu/vsWEKTBd8HJYiWKuA7YW+bM9C3teQKqkpfHiwTKqKzKM42pRsDIg8ENLoUl/Up+rELFMawFD2Wl+DIpQ/Cor57UM6z/4zk7UNyE4IxpkAXWkRMdiDJ1SeYwbw7syIsX4O8C+SyVe7gXo2bJCwl04WrlNVFTKpSgi5xwU6Lw3wQjf/T5Eh372yzCOKSX/1M+EjaGfoCAWryGTAVnmt2+C11VYYhmbfAGUYx5d7GaBZVmXIHGhqBjF3E9mSGGjYupCG8Vug1zk9lGxzk00lFgJsnNeecm+I8hI7nv4ygOM/ejCt1XnITxk+gHXseoJ92n00xPXAZFXaYjRwZwtvdmfydgAbgsHVITFqCqE9CAateGr6sk5hnOecvRF/eTXK3taN54qIgJGW+n4vQejrMVVn8ebRbAwOMRXSAQPD5r/8o6u/RDil1fDhsKORlFJGEHe61VdOmiIbOMKJyUIYKdpjeMVHEo0wpsAKvG8+je9br68KbHtq2NhkChBN34eaDgg2+gHumZooIl99xiBuzNjAMg5IInQvnE7vviYXhBNW3FRbUFAQG8xhQJDhRIawJmr7FPGECKKADTAVFQD+llTKCvaXjiXjRRXOVvjmCmEdrtoJDCMKHFiEsBxi4sWr2RfeUdtK4qU7pChkgKPKulah+sZiSgqy6aQlgG7ZoBTs5wxVeB0rkGRK0ypd0FTr1TryuBIRKoM8nzToPFcTF6UKvtppmpxf0QlPlt9GC6zyxB/GJXtb++/39Vs4axc1fXwB6V81rSttCK6fxPlVXEobTthwImsEahl4QgZVW4mfx21fyDy5oEAcF1wmKkMlvLImNcdwOFucsboVfSFBFhv/4QVioyxIzGjZFgqXbAr5jQLtb8S0gh2pLJAv7EkVYpG1CCkDw01mQ2KdLe1F6sPwVYLEADsZI21P+zU4v0dfATD1wPjpeH1w42Z8EPP/7OzMBZNTB1pUyZpGg/wDvXwpy0p39hf+kaJMMKUZUl1QwFSP6RIqw9ge6BKc4mTLXzGzQlrgip0tohfv5O/X6ZUvFns+EnvdPFTWw7/q80IiutZsZriGcGKE6KInyCLUe9EPB0XNIN0KBSk1FQ/Af32ld2Z/zWXKToa8o9WJq/slte5xwpXUCj4MU7VjALnmV6Qy2kBG9rULpMdZsXIDix/X6RMzosGa8ernC3OHeF8f/UDR+Zrd3JeWlPZVeb/J/dLNWYslJuPgxdvl870hY/LT04+uWRTc8ytYjaBQSx05XK8o3zqbMI3zmPxBVgnzen8AqB4LpWGabNl1zXf7pXh0J1Pp7uiA6aP8/sySpLtr/gjnicrgjmohW2u6Ijtqt67pd8vVn4GvkoDY+o/OACv/85Yi1g4QXyTFK4/ckgI0gWKFZrTLBcWvSjrru81VmGfZbvVcvcdfDFTIZqNAtvZ4EUEDXdx25YNILQpGM6/rKKpmutMerG+5OpRJs1DgIJfHRrZzETaoND0XCDu94mx0PDmV+i4QfXsRJJB38O2hkQuaqtS2pgAdjyx0CKhIx/N3Q0nnNsn45mevHoxP4QV5EBtNa48ytIER2R6LqnNaLLMfxXciI/TWfwtLHi9N1NlAjVw65FCWY1v6Ywz0u2edtFt93XKfRYcBGonKyU1HtFqYVJ2T7baMK135HqIQvV6pfiLQniZ+l88JIAIE5byaOet88HsR87mSKpIyNPVgJ86OqnAxcnQBZ3ktwH1FMI0H1DQhYY5Orku62Z2wb0AeahMnCdoKL03tw2X9FejjzM9jCYlz/hbRnBcSYUl96VlidH2A==","x296":"","x3":1782102072173,"x30":"1080,2400,440","x301":"ABSENT,ABSENT","x302":"1014356168587457B374ACD7A2D0A0E2","x303":"MEQCIESxaeVFjjAhHmqyU3qQiZXdN6JOtxKDIYl+M5AXKgX2AiAf1HPQ991g4bOAV3NSf7GT2lWgry2mK5Ae2sv/t88pKw==","x304":2,"x305":-3,"x306":{"deviceID":-1869414384,"eglImplementation":"meow","error":"","maxRenderbufferSize":0,"maxTextureSize":0,"renderer":"Mali-G57 MC2","shadingLanguageVersion":"OpenGL ES GLSL ES 3.20","success":true,"totalMemory":5793402880,"vendor":"ARM","vendorID":5045,"version":"OpenGL ES 3.2 v1.r32p1-01eac0.0a0b917d9265b4c01be9925306306139"},"x307":3,"x308":{"3":"07C6CBB81F9B7F3BFB9324CC4CBE9351","s":3},"x31":25,"x310":"eyJhbGciOiJBMjU2S1ciLCJlbmMiOiJBMjU2R0NNIn0.2pnkEY11tB3F5ybfn4yw8P24uTyOd1torATjuBhqNnqY0tDJ5185cA.EEePbDCforB6DxTG.Mj7kjcE93A3VoRf0HJs3TOVF-qW4oJCeK25TDF3_eJX1q-kYBJ9jnTpY4WAzwABdmgAfZwdOC1GfG3vNybMQ9W_8RqPf-RlFjHybern1kCPb95GDdSrs_l0zOucUtTScCCeIZCb6sZ2j9YU-THY50Wjx0Fekp92xSp1WkRV31l-3ruxAcWl2MUDp78_tTrMWatDI7eXgbzgNYgby7Ro3lU-BTI1U4RMKlecq9UwsAuoYK_DnA-8bjtYAShytMlTfGPVp_h7FZ9YcQq-q9zKXvGTPg-DRe1WEjoYxzFJADNsrHEzTw5jHtXKbUJwuBJlE7QBA5qIYfL2dsQkbivC-CygHrtsUjAw8pJdairTdOQStt4SvRupi9otegnlZEBxMyIDCmsisCaqbKo-CMAFEMDdqJTzTcF19-0FDnO7EfGd_wsRE82GDgyhBso2mcNDAI6Kd5gl2Z7LyDR-Tm8cxsEfny560fft3bwl0Amb-yz5PFDcCuIalNe04dNT8fFN5a2Jn05Fn2AzBE9neenvYPNzbOuoBCuiemlenn7UKs4cWtQKnjWfTAIKRLaCo1OMbSB8nftXrwnKkubHbjAOBNai2M2QudyFZrOL6sKQz8HsiL8Wyr1MdRNIddvjmu0SKYZYryzmXcqfOkFHRPVFFic9bOsxfHEDpGDjSvqsI9Lz9deHOJvywIH-ECWtExfrip1lnXBo6mHY6Fvt1DZNJA1pByvC2byye-I48JabQWH-lIgd803I5EjlxXGD3teTvqDASbECqn4bE9FkE1T4aQCR8FPgDi0E-08enRdP41yThRlcvNeUGGdZI4D1S4hfmuzGUjPKnQ1p7CMzCadzDczQAD2yh5ukXav0bF_IVGCamwAHpRFC5Jj24JQsmEVwcOzkf7PyuP1Thw0w51wrTgCxNcUPmMIjJqaXFuTqMHodLpWm9vP8hCaJEbaxZWmWaV_ZHyNC_IQf9vi8on1hNHwuKoSZD_o4P-O1MsbHX43q9KPHwIllOcqN2hiv1c-zCeAA-fGVgyLcmdzalIHoqD9Y4hfmNQs9gag8ngNA77AM-TWVSTux7lMiglxTrYULaNYiz3qGdpBtKBwJyIAUyIKWpEXT-_ispNkejPRIme8ZOXFING1b39WCbw2IudXDJESqveancV7LvMCsa-6ZoVLl6iFiU3_B4XX92LzZfOOkvyjbOQmogrnIjfQnERiIt2U9nNVWZMMDFFjrrhbM1B3tHFoe5KLr4t8Cs2P3HJ9kcU7NQr_QdfOkmjL2BJszwEt9fBQQ_wCK-9iavONMfYqlt7uaIWmONScPCFX7tLg4eyg95Y64NNUDj91PXHofhTetZitltkvO6zMFyd0gr5z48-bEEb090gU0adjr2JrQz3Xps4VAxh8u-I49jdI1nuN1L8epPHEu_65qc65ghabqrzj_tZeprXV1D4bks5_-nIN42EO8Wy6ZIn-u4-QydgMPKg9E0lOSXtc3D3PWVRM6K2Wdc9DatSWHYb_wbe2EfuSfsQZEbjPnLXRiRztDq4vSdprsS8RObKkOMi_qIhQdOjyuUMXvdrGNCvyEV_hDkXuq0COA91GcMIlEYrfD0dGohTmpL4XLOUtAfvOdnA4_bfqCNimCVUhOHQ3stgj2CKWBm.kJjL7zRFI2eH8dWw0yC4DA","x312":[0,94,0,0,0,0,0,0,512,0,568,94,0,0,0,0,0,0,0,0],"x32":1,"x33":5,"x34":100,"x35":100,"x36":1,"x37":0,"x38":1,"x39":"adb","x4":1782102072173,"x40":1,"x41":"","x42":"","x43":"wifi","x44":1782115646112,"x45":7139,"x46":"c7ce9db572cecdc4","x47":"63926370-8053-4c35-b0f1-2df84fd3346","x48":"/data/user/0/com.xingin.xhs","x49":"/data/app/~~9NJNOADHLIr1VH97okgjSw==/com.xingin.xhs-K7TakgAuaEZrLAF52M1Btg==/base.apk","x5":"GooglePlay","x50":0,"x51":"com.sohu.inputmethod.sogou.xiaomi/.SogouIME","x52":"com.baidu.input_mi/.ImeService:com.iflytek.inputmethod.miui/.FlyIME:com.sohu.inputmethod.sogou.xiaomi/.SogouIME","x53":1,"x54":0,"x55":0,"x58":[{"n":"lsm6dso_acc","t":1,"v":"InvenSense","ve":1},{"n":"mmc5603","t":2,"v":"Memsic","ve":1},{"n":"ORIENTATION","t":3,"v":"MTK","ve":1},{"n":"lsm6dso_gyro","t":4,"v":"InvenSense","ve":1},{"n":"tcs3701_l","t":5,"v":"AMS","ve":1},{"n":"tcs3701_p","t":8,"v":"AMS","ve":1},{"n":"GRAVITY","t":9,"v":"MTK","ve":1},{"n":"LINEARACCEL","t":10,"v":"MTK","ve":1},{"n":"ROTATION_VECTOR","t":11,"v":"MTK","ve":1},{"n":"UNCALI_MAG","t":14,"v":"MTK","ve":1},{"n":"GAME_ROTATION_VECTOR","t":15,"v":"MTK","ve":1},{"n":"UNCALI_GYRO","t":16,"v":"MTK","ve":1},{"n":"SIGNIFICANT_MOTION","t":17,"v":"MTK","ve":1},{"n":"STEP_DETECTOR","t":18,"v":"MTK","ve":1},{"n":"STEP_COUNTER","t":19,"v":"MTK","ve":1},{"n":"GEOMAGNETIC_ROTATION_VECTOR","t":20,"v":"MTK","ve":1},{"n":"TILT_DETECTOR","t":22,"v":"MTK","ve":1},{"n":"pickup  Wakeup","t":33171036,"v":"xiaomi","ve":1},{"n":"DEVICE_ORIENTATION","t":27,"v":"MTK","ve":1},{"n":"UNCALI_ACC","t":35,"v":"MTK","ve":1},{"n":"prox_factory_strm","t":33171005,"v":"xiaomi","ve":1},{"n":"als_factory_str","t":33171007,"v":"xiaomi","ve":1},{"n":"Aod  Wakeup","t":33171029,"v":"xiaomi","ve":1},{"n":"sar_algo","t":33171028,"v":"xiaomi","ve":1},{"n":"sar_algo_1","t":33171059,"v":"xiaomi","ve":1},{"n":"sar_algo_2","t":33171109,"v":"xiaomi","ve":1},{"n":"cct_factory_str","t":33171089,"v":"xiaomi","ve":1},{"n":"STEP_DETECTOR_WAKEUP","t":18,"v":"MTK","ve":1},{"n":"Touch Sensor","t":33171031,"v":"Xiaomi Large Area Detect","ve":1}],"x59":0,"x6":1782098607875,"x62":"com.linsheng.FATJS/com.linsheng.FATJS.MyAccessibilityService","x65":1,"x66":"adb","x67":"0000000000000000000000000000000000000000000000000000000000000000","x68":"50188/W4NJ02351","x69":"NA349W005842","x7":"mt6833","x70":17,"x71":1782115634970,"x72":1782102336622,"x73":1782114255960,"x76":8,"x77":"mt6833","x78":10314,"x79":28952,"x8":1715582733000,"x80":922,"x81":5827284992,"x82":2020679680,"x85":"7a7787eeb9aca4c8ef2418c35c19d194bacb3d82fbff8adf476d6bbfa12a3b55","x86":"F1662FABD856F3718828F89A7F07037DA97760A5","x87":1782115634975,"x89":"192.168.50.101","x9":"TP1A.220624.014","x90":3,"x92":35,"x93":3,"x97":"{\"d1\":\"109|110|117|129\",\"d10\":\"\",\"d11\":\"7|8|9\",\"d12\":\"\",\"d13\":\"\",\"d4\":\"\",\"d6\":\"\",\"d9\":\"\",\"s1\":\"0|0|-|0|0|0|0\",\"s10\":\"0|*|0|*|*\",\"s11\":\"*|0|0\",\"s2\":\"1|*|0\",\"s3\":\"*|0|0|0|0|0|0\",\"s4\":\"*|*|*|*\",\"s5\":\"0|*|*|*|0|0|0|0|0|*|0|0\",\"s6\":\"*|0|0|*|0|0|0|0|0|*|0|-\",\"s7\":\"0|0|0|0\",\"s8\":\"0|-|0|0|0|0|0\",\"s9\":\"*|0|-|0\"}","x98":"25","x99":"4143983237"}
```

## x295 专项：白盒加密的「检测取证报告(detect-detail)」——明文 JSON 已 frida 实锤

x295 是 devfp 里唯一的**白盒加密字段**（非 JWE、非信封 d）：标准 base64 ⇒ 二进制密文，**长度随检测发现量变化**（样本 `P/REcJ2i3uE…` = 320 字符/240B，发现少的干净环境；插桩环境下明文涨到 1.3KB+）。

> ⚠️ 更正：早前推断「x295=设备身份 ID 簇(x170/x171/x173/x85)」是**错的**——那是同线程旁边 devfp map 组装的串扰。下面是 frida 直接抓到的加密前明文,实锤。

**真身：x295 = 把「检测/完整性取证报告」序列化成 JSON、再白盒加密**。明文 JSON 结构(frida 实测,与本文档 §「json 来源」记录的 **detect-detail (`cap/detect-detail_30e750.json`) 同一棵树**)：
```json
{
  "global": {
    "code-patch-check": ["detect tiny code patch!", "hash[0] = … hash[1] = …", … 9 对 xxHash3-128],
    "code-patch-prepare": ["sections[0] = 0x…ec0 - 0x…a00", … 9 段 .text 区间]
  },
  "s1": {}, "s11": {},
  "s6": {"9": ["", "FD 7B BF A9"]},                    // 抓到的 inline-hook 字节(ARM64 stp 序言)
  "s7": {"4": ["", "package name: com.xingin.xhs"]},   // 反克隆
  "t":  {"26": ["", "/data/data/com.xingin.xhs", "/proc/self/maps"]}  // 路径取证
}
```
- `global.code-patch-check` = 代码完整性自检(就是 §「global 专项」的 xxHash3-128)。**实测命中 `detect tiny code patch!`** —— frida/QBDI 插桩被它逮到;
- `s6/s7/t/...` = 各检测叶子的**实锤证据原文**(被改字节、被 hook 函数+maps、敏感路径);`s1/s11:{}` = 本项无命中。

**产出链(frida + 10G QBDI trace 三方印证)**
```
检测结果对象树(serde Value: {global,s1,s6,s7,t,…})
 └ sub_28D92C(x295 构造器, qword_7421B8) → sub_14C374(once_cell) → sub_6C666C → sub_6B4558(白盒编码器)
      └ 内部调用 #1 序列化器 json_ser_new(0x160F68) 把对象树 → JSON 明文 byte 数组   ← 这就是上面那段 JSON
           └ 白盒加密(全程 BR X9, 10G trace 里 sub_6B4558 单次跑 237M 指令不返回) → 240B+ → base64 → x295
```

**实锤方法(关键)**：作用域 hook `frida/hook_x295_plaintext.js` —— 以 `sub_28D92C` 为线程局部窗口,窗口内收集所有 `json_ser_new` 输出。实测 3 段：`#0="null"`、`#1=上面的取证 JSON(1352B)`、`#2=detect-bitmap {"10":"*",…}(169B)`。**最大段 #1 即 x295 加密前明文**。

**结论**
- **x295 = 白盒加密的检测取证报告(detect-detail)**：装的是「哪些检测命中 + 命中的具体证据原文」,不是设备 ID;
- **长度自解释**：发现越多明文越长(干净 240B → 插桩 1.3KB+),印证它是变长取证桶;
- **为什么用最硬白盒**：它是检测的**实锤证据**,攻击者最想抹/伪造的就是这个 → 加密等级拉满,逼「篡改明文 bitmap 也没用,证据在 x295 里改不动」;
- **`s`/`d` bitmap 说「哪几项命中」,x295 说「命中的证据」**——加密的 detail/forensics 上报通道;
- **方法论**：加密输入底层一定是 byte 数组;白盒若内部调用已知序列化器(`json_ser_new`),作用域 hook 该序列化器即可拿到加密前明文,不必逆白盒、不必抓连续缓冲。

============================================== 现场采集 vs 仅搬运 ============================================

## 现场采集 vs 仅搬运——本 trace 实锤（run: `trace_libtiny.so.bin`，770592 指令）

> 口径：**「现场采集」= 值在被 trace 的这段执行里通过 syscall / `__system_property_*` / 本地计算 当场产生**；
> **「仅搬运」= 值在被 trace 前(库初始化 / Java 侧 JNI)就已算好/缓存，本段执行只做 克隆 → 打 tag → 序列化**。
> 判定法：对字段写入点 `where_written`/`trace_value`/`taint`——追到 syscall 返回值 / 属性读 / native 算法 = 现场采集；追到常驻全局或 `memcpy`(源无插桩写) = 仅搬运。
>
> ⚠️ **本 trace 的采集面与 section 1/2 的旧表不同**（那些表混了 app 侧 JSON 与更大的另一条 run）。本 trace **实测 syscall 仅 35 次**：`clock_gettime×6 / fstatat×24 / uname×1 / getpid×1 / gettid×1 / prctl×2`，**无 statfs、无 openat、无批量属性读**；属性读全程**只有 1 次**（`gsm.sim.state`）。故凡 section 1 里标「statfs/openat(/proc random)/大批属性直取」的字段，**在这条 trace 里没发生**——它们属于别的采集 run 或 init 期。下表只登记**本 trace 亲眼看到**的现场采集。

### 一、现场采集原语总表（seq/参数/返回 均可复核）

| 原语 | seq | 关键参数 / 返回 | 采集内容 | 归属字段(置信度) |
|---|---|---|---|---|
| `uname()` | 191208 | ret=0 | `machine`/`release`/`version` | **x26/x27/x28**（高，section1 已印证） |
| `getpid()` | 308274 | ret=0x3a0a=14858 | 进程 PID | **x79**（高） |
| `gettid()` | 308517 | ret=0x3af6=15094 | 主线程 TID | 计数/线程类字段（中，需 taint） |
| `clock_gettime(CLOCK_REALTIME=0)` | 821 / 25880 / 285352 / 569977 / 760071 | ret=0 | 墙钟毫秒（采集时刻） | **x44/x243/x260/x289** 等时间戳（高） |
| `clock_gettime(CLOCK_BOOTTIME=7)` | 25837 | ret=0 | 开机以来时长（uptime） | uptime 类字段（中） |
| `__system_property_find`+`read_callback` | 711577 / 712074 | name=`gsm.sim.state` | SIM 卡状态 | **x301**（高） |
| `prctl(0x3=PR_GET_DUMPABLE)` | 667970 | ret=0 | 进程可 dump 位 | 反调试/环境标志 J 类（中） |
| `prctl(0x27=PR_GET_NO_NEW_PRIVS)` | 671119 | ret=0 | no_new_privs 位 | 反调试/环境标志 J 类（中） |
| `fstatat()` ×24 | 349988–682337 | 见下分组 | 目录/文件 存在性+stat 指纹 | x165 类 / detect 文件扫描（见下） |
| native **MD5** | 402182–404279 | — | 7 指针+时间种子 → token | **x137**（高，见「x137 专项」） |
| native **CRC32** | （查表实现） | — | s* 矩阵串校验 | **x99**（高，见 section1 H 类） |

### 二、`fstatat` ×24 的三组语义（path 参数逐条实锤）

| 组 | seq 区间 | 路径 | 目的 |
|---|---|---|---|
| **A. 系统布局探测** | 349988–350504 | `/system` `/etc` `/init` `/sdcard` `/bin` | 顶层目录存在性 → root/改机/模拟器环境判定 |
| **B. 外置存储/媒体目录枚举** | 570075–571893 | `/storage/emulated/0/{Movies,Music,Ringtones,Notifications,Pictures,Podcasts,Download,Alarms}` + `Android/obb/.nomedia` + `Android/data/.nomedia` | 媒体目录 mtime/存在性 → 真机使用痕迹指纹 |
| **C. data 分区/GMS 探测** | 572089–573366 | `/data/vendor_ce(/0)` `/data/user/0/com.google.android.gms/code_cache` `/data/system_ce` `/data/system/packages-warnings.xml` `/data/system/last-header.txt` `/data/misc_ce` `/data/data/com.google.android.gms/code_cache` | GMS 存在性 + 系统文件 mtime → 真机/GMS 指纹 + 环境校验 |
| **D. build.prop** | 682337 | `/system/build.prop` | 构建属性文件 stat |

> A/D 偏**环境校验**（对应 J 类环境标志与 section3 检测），B/C 偏**文件系统时间指纹**（x165 族）。精确「哪条 stat 进哪个 x/d 键」需对各 fstatat 结果做正向 taint——本表先锁定 path 与目的这两项地面真相。

### 三、仅搬运字段（本 trace 不采集，只克隆+序列化）

| 字段族 | 值 | trace 内行为 | 真值来源（在 trace 外） |
|---|---|---|---|
| **x0** | com.xingin.xhs | 从全局 `libtiny+0x746c08` 克隆(`0x132a00` 例程) → tag=3 → 写 JSON | init 期 JNI `Context.getPackageName` 已缓存 |
| **x1/x2/x5** | 版本/渠道 | 同上，紧凑字符串克隆 | init 期 JNI，缓存于 libtiny 全局 |
| **x111/x85/x86/x145/x146** | SHA-224/256/1 摘要 | libtiny 只 `memcpy`+重组+序列化（`analyze_crypto` 对 SHA 系零命中） | Java 侧 `MessageDigest` 算好，JNI 回传（见各「专项」） |
| **x286 等** | 内嵌 token | 从存储/资源 `memcpy` 原样写入 | 存储/资源，非本段计算 |

### 四、x0 采集链（仅搬运的标准范例，逐 seq 实锤）

```
libtiny.so + 0x746c08   常驻全局，紧凑字符串 [0x1c]"com.xingin.xhs"
    │  (init 期经 JNI Context.getPackageName 采集并缓存；本 trace 内无任何写指令)
    ▼ seq 9616-9618  ldr q0 / str q0  (克隆例程 0x132a00–0x132a8c；首字节 0x1c 位0=0 → inline 分支)
栈拷贝 0x70b515e2f0
    ▼ seq 10237-10239  str q0 @0x132a28  (trace_value: memcpy_src=0x70b515e2f0)
堆拷贝 0x70ac79e020  =[0x1c]"com.xingin.xhs\0"
    ▼ 组装 serde Value{ tag=3(String) @+0x00, ptr=0x70ac79e020 @+0x08 } @ 0x70b515e2e0
    ▼ seq 12094-12102  采集点 libtiny+0x1cf234：ldrb 取 tag=3 → strb 写入序列化输出缓冲 0x70acb88988
最终 JSON: "x0":"com.xingin.xhs"
```

> 采集点记录的 16B（`03 …| ptr`）= 此 Value 枚举体：tag=3 即 serde `Value::String`（枚举序 Null0/Bool1/Number2/String3/Array4/Object5），ptr 指向堆字符串。x0 跨 run 不变，正因它是「搬运缓存值」而非「现场取值」。


============================================== 字段主表(按 key 升序) ============================================

## 字段主表：key → 值 → 采集方式（含证据判定）

> **判定标准（✓/✗ = 有无实锤；现场采集 vs 搬运 的区分放在「采集方式」列）**：
> - **✓** = **有实锤**：trace/IDA/Frida 任一给出确证（来源字段+采集/搬运机制，附 seq/地址/明文）。含两类：
>   - `现场采集` —— 值在本次执行当场产生（syscall/属性读/本地计算/运行期生成）；
>   - `搬运(已实锤)` —— 值在 Java/init/存储侧产生，libtiny 只 JNI 读字段/克隆/memcpy/序列化，但**这条搬运链已被完整实锤**（如 x0/x1/x2/x8/x49 = PackageInfo/ApplicationInfo 字段，IDA 明文+trace+Frida 三方）。
> - **✗** = **无实锤**：纯值语义猜测，没有 trace/IDA 证据（未观测到对应 syscall/属性读/未 taint 写入点）。
> - `[别run]` = 证据出自另一条 trace，不在本 run 内（但 traceui 确实分析到了）。
>
> 诚实提示：大量 `属性 ro.*` 与 `JNI` 字段是**从值反推**的（如 x10 长得像 `ro.build.fingerprint`），本 trace 里**根本没发生**那些读取——归 ✗。搬运类只要搬运链实锤即 ✓，但采集方式列会写明「搬运」，不等同现场采集。

| key | 值 | 证据 | 采集方式 | 实锤位置 / 为何✗ |
|---|---|:---:|---|---|
| x0 | com.xingin.xhs | ✓ | 搬运(已实锤)：非现场采集,源在 Java 层 | 全局 `libtiny+0x746c08`(懒初始化缓存,内联 CompactString `1c`+"com.xingin.xhs")→克隆`0x132a00`(seq9618)→采集点`0x1cf234`(seq12094)。**Frida 实锤写入者=`sub_29C660`**(once-init,X8=&0x746c08,写前全0→写后填串;fp_collect@`0x1c9eac` 触发)。**IDA+trace 双实锤填充者=`sub_2BFF48`**:对一个 Java 对象逐字段读入缓存。**单函数 trace(入口=0x29c660,25617行)实锤 JNI 序列**:seq3873 `blr [env+0x2f8=760]`=`GetObjectField(obj,fieldID qword_74EF88)`→jstring;seq3878 `[env+0x720=1824]`=`ExceptionCheck`;seq3887 `[env+0x548=1352]`=`GetStringUTFChars`→返回 buf `0x70b6bf7c60`="com.xingin.xhs";seq3893+ strlen 转 CompactString。**源 Java 字段=`android.content.pm.PackageInfo.packageName`**(IDA `sub_4BC564` 明文:`FindClass("android/content/pm/PackageInfo")`+`GetFieldID("packageName","Ljava/lang/String;")`→qword_74EF88)⇒ app 侧 `PackageManager.getPackageInfo()` 得 PackageInfo 传入,libtiny JNI 反射读字段 |
| x1 | 9.32.0 | ✓ | 搬运(已实锤)：非现场采集,源在 Java 层 | 源=`PackageInfo.versionName`(qword_74EF90)。同 x0 缓存,x1 在 `+0x746c38`。`sub_2BFF48` JNI 反射读。**同组 PackageInfo 字段**(sub_4BC564 明文):x2=`versionCode`(GetIntField,qword_74EFA8)、x8=`firstInstallTime`(GetLongField,qword_74EF98)、`lastUpdateTime`(qword_74EFA0)、x49 系=`applicationInfo`(qword_74EFB0)。libtiny 不自调 getPackageName/versionName |
| x2 | 9320802 | ✓ | 搬运(已实锤)：`PackageInfo.versionCode` | IDA明文 `sub_4BC564`:`GetFieldID("versionCode","I")`→qword_74EFA8;`sub_2BFF48` `GetIntField` 读入。值 9320802 匹配。源在 Java,非现场采集 |
| x3 | 1782199052916 | ✓ | 搬运(已实锤)：`PackageInfo.lastUpdateTime` | IDA明文 `GetFieldID("lastUpdateTime","J")`→qword_74EFA0,`GetLongField`。trace 实锤 fp_collect 从缓存克隆:seq52147 `ldur q0,[cache+0x54]`/seq52148 `ldur q1,[cache+0x48]`(缓存 +0x50 firstInstall/+0x58 lastUpdate,本run 均=1782654430983 全新装相等)。值为**安装/更新期时间戳,非采集时刻** ⇒ 排除 currentTimeMillis/clock_gettime,源在 Java PackageInfo |
| x4 | 1782199052916 | ✓ | 搬运(已实锤)：`PackageInfo.lastUpdateTime`(同 x3) | 与 x3 同值同源(读一次填两键);缓存搬运机制同 x0。x8=`firstInstallTime`(2024-05),x3/x4=`lastUpdateTime`(2026-06) |
| x5 | GooglePlay | ✓ | 搬运(已实锤)：分发渠道名(app 配置对象字段) | trace 实锤:seq66189 `ldr x8,[全局 0x6d9d20]`=app 配置对象堆指针→seq66193 `add x1=x8+off`→源 `0x70debc9410`(内联 CompactString `0x14`+"GooglePlay")→seq66205 克隆 `0x132a00`。源无插桩写=trace 前填好。**非 getInstallerPackageName**(值是渠道名非包名),是打包渠道(BuildConfig/渠道文件),Java 存入配置对象 JNI 传入,libtiny 只克隆序列化 |
| x6 | 1782098607876 | ✓ | 现场采集：**开机墙钟时刻** = CLOCK_REALTIME − uptime | trace 实锤:seq68311 `clock_gettime(BOOTTIME=0x7)`→uptime ms(x21);seq68354 `clock_gettime(REALTIME=0x0)`→{sec,nsec};seq68372 `madd x9=sec×1000−uptime_ms`+seq68373 `add nsec_ms`→x0=开机时刻(so 0x29c1c8–0x29c1e0)。本run=1783601438320。.md 值 2026-06-01=开机时刻(与 x165 radio/debuggerd_prop mtime 一致);采集时刻−x6≈2.16天 uptime。**非搬运,libtiny 两个 syscall 现算** |
| x7 | mt6833 | ✓ | 现场采集：属性 `ro.board.platform` | 属性名内存解密实锤(0x6fe2321b60@77912)。§B 机制 |
| x8 | 1715582733000 | ✓ | 搬运(已实锤)：`PackageInfo.firstInstallTime` | IDA明文:`GetFieldID("firstInstallTime","J")`→qword_74EF98;`GetLongField` 读入。值 2024-05 匹配首装时间。源在 Java |
| x9 | TP1A.220624.014 | ✓ | 现场采集：属性 `ro.build.display.id` | 属性名内存解密实锤(0x71010fe400@99656)。§B |
| x10 | Redmi/gold/…/release-keys | ✓ | 现场采集：属性 `ro.build.fingerprint` | 属性名内存解密实锤(0x71010fe3c0@111296)。§B |
| x11 | pangu-…-6w6nd | ✓ | 现场采集：属性 `ro.build.host` | 属性名内存解密实锤(0x70fbb51240@120275)。§B |
| x12 | TP1A.220624.014 | ✓ | 现场采集：属性 `ro.build.id` | 属性名内存解密实锤(0x70fbb513a0@128300)。§B |
| x13 | release-keys | ✓ | 现场采集：属性 `ro.build.tags` | 属性名内存解密实锤(0x70fbb510c0@137005)。§B |
| x14 | user | ✓ | 现场采集：属性 `ro.build.type` | 属性名内存解密实锤(0x70fbb51e00@145700)。§B |
| x15 | V14.0.11.0.TNQCNXM | ✓ | 现场采集：属性 `ro.build.version.incremental` | 属性名内存解密实锤(0x6fdb489660@160929)。§B |
| x16 | 13 | ✓ | 现场采集：属性 `ro.build.version.release` | 属性名内存解密实锤(0x6fdb489640@174701)。§B |
| x17 | 33 | ✓ | 现场采集：属性 `ro.build.version.sdk` | 属性名内存解密(ro.build.version.s* 系),值 33=sdk。§B |
| x18 | 2026-06-05 | ✓ | 现场采集：属性 `ro.build.version.security_patch` | 属性名内存解密实锤(0x6fdb4897a0@193200)。§B |
| x19 | gold | ✓ | 现场采集：属性 `ro.product.device` | 属性名内存解密实锤(0x6fa9c21b40@214256)。§B |
| x20 | Redmi | ✓ | 现场采集：属性 `ro.product.brand` | 属性名 `sub_138D58` 现场逐字符解密(内存实锤"ro.product.brand"@seq10174,0x7092bd7560)→查属性区取值"Redmi"(结构体 `0x711f5bd280` +0x10=名/+0x28=值)→seq11633 克隆 `0x132a00`。属性区读无 syscall/无 PLT(见 §B) |
| x21 | arm64-v8a,armeabi-v7a,armeabi | ✓ | 现场采集：属性 `ro.product.cpu.abilist` | 属性名内存解密实锤(0x7092d9c1a0@23465)。§B |
| x22 | gold | ✓ | 现场采集：属性(product 设备代号) | 属性组机制同 §B(内存见 ro.product.name/board);值 gold=设备代号 |
| x23 | Xiaomi | ✓ | 现场采集：属性 `ro.product.manufacturer` | 属性名内存解密实锤(0x6fa9c21ea0@226912)。§B |
| x24 | 2312DRAABC | ✓ | 现场采集：属性 `ro.product.model` | 属性名内存解密实锤(0x70f03dc6f0@230606)。§B |
| x25 | gold | ✓ | 现场采集：属性 `ro.product.name`(设备代号) | 属性名内存解密实锤(0x7092d65580 "ro.product.name")。§B |
| x26 | aarch64 | ✓ | 现场采集：uname().machine | `uname()` syscall @seq191208（本 trace 实锤）；值即 machine |
| x27 | 5.10.198-GKI-Yuri | ✓ | 现场采集：uname().release | 同 uname@191208 |
| x28 | #1 SMP PREEMPT … 2025 | ✓ | 现场采集：uname().version | 同 uname@191208 |
| x29 | MOLY.…P48,…P48 | ✓ | 现场采集：属性 `gsm.version.baseband` | 属性名内存解密实锤(0x7092bbb2e0@250389)。§B |
| x30 | 1080,2400,440 | ✓ | 搬运(已实锤)：屏幕 宽,高,DPI(DisplayMetrics) | trace 实锤:源 `0x70debcde20`(=libtiny+0x746e20)无插桩写=预拼好的缓存,seq254131-133 克隆 `0x132a00`(内联 len13)→x30。IDA `sub_2C5D48` 懒初始化,从配置 map `byte_747758` 查值 `qword_746E20`。**值现成(无 libtiny itoa 拼接)** ⇒ Java 侧从 DisplayMetrics 取 w/h/densityDpi 格式化,放配置 map,JNI 传入,libtiny 只查+克隆 |
| x31 | 5 | ✓ | 现场采集：JNI `Settings.System.getInt("screen_brightness")`=屏幕亮度 | trace 逐指令实锤:seq264451 取设置名 C 串 "screen_brightness"→seq264462 `NewStringUTF`(env+0x538)→sub_4BEBE8 `FindClass("android/provider/Settings$System")`+`GetMethodID("getInt","(…ContentResolver;String;)I")`→CallIntMethod→seq264683 返回 w0=5→Value 构造(0x1d4c98,tag=5 是 i32 类型常量非 serde Object)→采集点 0x1d0618(seq267178)。**非"内部计数",是屏幕亮度设置** |
| x37 | 0 | ✓ | 现场采集：JNI `Settings.getInt("accessibility_enabled")`=无障碍是否开启 | 采集点 0x1cc824(Frida)→trace 实锤:seq276002 取设置名 "accessibility_enabled"→seq276005 NewStringUTF→`sub_4BEA18` CallStaticIntMethodV(env+0x410=idx130,Settings.getInt)→seq276075 返回 w0=0→Value(tag=5 i32)→采集点 0x1cc824(seq278565)。**反自动化检测**(查无障碍服务),值 0=未开启。setup 共用 x31 的 `sub_4BEBE8`(Settings$System) |
| x38 | 1 | ✓ | 现场采集：JNI `Settings.Global.getInt("adb_enabled")`=ADB调试是否开启 | 采集点 0x1bbe50(Frida)→trace 实锤:seq283488 取设置名 "adb_enabled"→seq283497 NewStringUTF→`sub_4BE8E0`(Settings$Global setup)+`sub_4BEA18` CallStaticIntMethodV→seq283566 返回 w0=1→Value(tag=5 i32)→采集点 0x1bbe50(seq286175)。**反调试/环境检测**,值1=ADB开(本run 用 ADB 调试)。⚠️ doc 早期把 ADB_ENABLED 错标给 x39,实为 x38 |
| x39 | adb | ✓ | 现场采集：系统属性 `sys.usb.state`=当前 USB 模式 | 采集点 0x1cb838(Frida,tag=3 String)→trace 实锤:属性名 "sys.usb.state"(内联串@对象 0x70d5a72a00)→属性区读值 "adb"→libtiny 对值做子串搜索(seq314196 逐字符比对)→内联 CompactString 克隆链(seq314252→314383)→采集点 0x1cb838(seq316802)。**"adb"=USB 处于 ADB 调试模式**(反调试/环境)。⚠️ 与 x38 区分:x38=Settings.Global.adb_enabled(开关设置),x39=sys.usb.state(当前 USB 状态) |
| x40 | 1 | ✓ | 现场采集：JNI `TelephonyManager.getSimState()`=1(SIM_STATE_ABSENT,无卡) | **Frida ToReflectedMethod 精准定死**(hook_x40_method.js @0x29d48c):obj.class=`android.telephony.TelephonyManager`,method=`getSimState()`,methodID=0x7067d318。trace:seq317160 CallIntMethodV 返回 1→拷进 fp_collect scratch `libtiny+0x747e70`(非持久缓存)→采集点 0x1bc570。值 1=ABSENT,与 x301="ABSENT,ABSENT" 一致。setup=`sub_4BFB60`(对 TelephonyManager 对象解析 ~10 个 int 方法 qword_74F310..358,x40=第1个)⇒ 附近 J 族(x93/x267 等)疑同类 telephony 字段 |
| x41 | "" | ✗ | 空/占位 | 无 |
| x42 | "" | ✗ | 空/占位 | 无 |
| x43 | unknown | ✗ | 状态枚举 | 未 taint |
| x44 | 1782285462973 | ✓ | 现场采集：clock_gettime(REALTIME)=currentTimeMillis | trace 实锤:`clock_gettime(0x0)` 现场读墙钟,seq327836 `ldp sec,nsec`→seq327851 `madd x0=sec×1000+nsec/1e6`(so 0x29c034-0x29c070,**无 uptime 相减**,区别于 x6)。realtime 读法在 seq821/327824/615554/805614 各调一次=采集时刻组(x44/x243/x260/x289,值聚在同一毫秒簇)。本run≈1783682724089 |
| x45 | 45 | ✗ | 计数/度量 | 未 taint |
| x46 | c7ce9db572cecdc4 | ✓ | 搬运(已实锤)：早期从存储/JNI 直取，非现场采集 | 文档专项：@seq11925 逐字符拼成（值来自存储，非本函数当场产生） |
| x47 | ac8d2894-…(boot_id) | ✓ | 现场采集：openat(/proc/…/boot_id) | 文档专项：openat 成功 fd=0x20f @seq102364 `[别run]` |
| x49 | /data/app/…/base.apk | ✓ | 搬运(已实锤)：`ApplicationInfo.sourceDir` | IDA明文 `sub_4BE6C4`:`FindClass("android/content/pm/ApplicationInfo")`+`GetFieldID("sourceDir","Ljava/lang/String;")`→qword_74F108;经 `PackageInfo.applicationInfo`(qword_74EFB0)取子对象再 `GetObjectField` 读。值=APK 路径匹配 |
| x68 | 50188/W4NJ02351 | ✓ | 属性/sysfs 探测 | 文档专项：`/sys/…/cid` 等 openat 失败 @seq232195 等 `[别run]` |
| x69 | NA349W005842 | ✓ | 属性扫描(ro.boot.serialno 族) | 文档专项：候选属性名 seq729k–818k 可见 `[别run]` |
| x70 | 21 | ✗ | 计数/度量 | 未 taint |
| x72 | 1782208387051 | ✗ | 疑 JNI 时间戳 | 未 trace |
| x73 | 1782284974620 | ✗ | 疑 JNI 时间戳 | 未 trace |
| x76 | 8 | ✗ | 计数/枚举 | 未 taint |
| x77 | mt6833 | ✗ | 疑属性 ro.board.platform | 值反推 |
| x78 | 10316 | ✗ | 疑 gettid/uid | gettid syscall 存在@308517 但**映射 x78 未证**（doc 自标"疑"） |
| x79 | 32759 | ✓ | 现场采集：getpid() | `getpid()` @seq308274（doc"返回值即此"，本 trace syscall 实锤） |
| x80 | 922 | ✗ | 计数 | 未 taint |
| x85 | 7a7787ee…a12a3b55 | ✓ | 搬运(已实锤)：SHA-256 Java 算 JNI 回传，非现场采集 | 专项：crypto 零命中 + trace_value writers=[]（libtiny 只 memcpy） |
| x86 | F1662FAB…/9835AABD… | ✓ | 搬运(已实锤)：SHA-1 Java 回传，String::push 重组 | 专项：成串@seq334121(so 0x13306c)，libtiny 未计算 |
| x87 | 1782285462498 | ✗ | 疑 JNI 时间戳 | 未 trace |
| x92 | 35 | ✗ | 计数/度量 | 未 taint |
| x93 | 3 | ✗ | 计数/度量 | 未 taint |
| x98 | "0" | ✗ | 字符串布尔 | 未 taint |
| x99 ⚠️ | 3928694620 | ✓ | 本地计算：CRC32 查表 | 专项：查表 so `0x1d48c4–0x1d48e8` |
| x110 | 9046d49b-…(uuid) | ✓ | 现场采集：openat(/proc/…/uuid) | 专项：openat 成功 fd=0x21d @seq352928 `[别run]` |
| x111 | 0x337d4cd6…368a53cb | ✓ | 搬运(已实锤)：SHA-224 Java 回传，非现场采集 | 专项：crypto 零命中 + trace_value writers=[]，memcpy 搬运链 seq749277+ |
| x120 | 0 | ✗ | 布尔标志 | 未 taint |
| x122 | 1 | ✗ | 布尔标志 | 未 taint |
| x123 | Dalvik/2.1.0 (…Android 13…) | ✗ | 疑 JNI http.agent | 串在 trace(@637706)但**方式**未证 |
| x125 | 2708138710 | ✗ | 大数值/校验 | 未 taint |
| x126 | [apex jars…] | ✗ | 疑 BOOTCLASSPATH | 有 BOOTCLASSPATH 读@seq373825 但**映射 x126 未证** |
| x128 | "" | ✗ | 空/占位 | 无 |
| x131 | 0 | ✗ | 布尔标志 | 未 taint |
| x134 | 157f29b9-…-d605bd0471f4 | ✓ | 搬运(已实锤)：从持久存储读出的安装 UUID，非现场生成 | 专项：最早@seq30067(so 0x4bb56c)，早于任何随机源（值早已落盘） |
| x137 | 655919F6…(每run变) | ✓ | 本地计算：native MD5(7指针+时间种子) | 专项：MD5Transform so`0x4524ec`,轮常量实锤@seq402182 |
| x145 | {com.xingin.xhs:7c80…} | ✓ | 搬运(已实锤)：包名→摘要 map，Java 回传，非现场采集 | 专项：源`0x73816e9d40` memcpy 搬运,trace_value writers=[]@seq407235 |
| x146 ⚠️ | 7c8067a8…077ac7d8c | ✗ | 疑 SHA-224 摘要 | doc 自标"疑",算法未证 |
| x155 | NA349W005842…111 | ✓ | 属性扫描(同 x69) | 专项：序列号属性扫描 `[别run]` |
| x165 | {路径→stat 指纹串} | ✓ | 现场采集：fstatat+statfs | 本 trace fstatat×24 path 实锤(seq349988–682337)；statfs `[别run]` |
| x170 | id_provider | ✗ | 代码字面量标签 | 未单独分析 |
| x171 | aa3c9779598403b9 | ✓ | JNI ANDROID_ID | 专项：key `android_id` 栈上构造@seq11614,取回@seq123598 |
| x173 | bf2949218a376f5b | ✓ | 本地计算：派生 ID | 专项：序列化区晚期生成@seq822311(so 0x132a28) |
| x174 | 79caf379-…(每run变) | ✓ | 现场采集：运行期生成 UUID | 专项：现场生成@seq822417(memcpy so 0x4fd478) |
| x180 ⚠️ | 6aa84e97-…(每run变) | ✓ | 现场采集：运行期生成 UUID | 专项：现场生成@seq822557 |
| x185 ⚠️ | IiGgS | ✗ | 疑本地计算 token | 算法未证 |
| x186 | -1 | ✗ | 不可用码 | 无 |
| x187 | -1 | ✗ | 不可用码 | 无 |
| x189 | 1781883842496…4076150800 | ✓ | 现场采集：=x165 key4 install_sessions | fstatat 实锤(同 x165) |
| x194 | "1" | ✗ | 字符串布尔 | 未 taint |
| x202 | "1" | ✗ | 字符串布尔 | 未 taint |
| x203 | "1" | ✗ | 字符串布尔 | 未 taint |
| x206 | 0 | ✗ | 布尔标志 | 未 taint |
| x207 | 0 | ✗ | 布尔标志 | 未 taint |
| x231 | 115014074368 | ✓ | 现场采集：statfs(data) | 专项：statfs 实锤@seq279797(svc so 0x2ce1f0) `[别run]` |
| x232 | 115014074368 | ✓ | 现场采集：statfs(总存储) | 同 statfs `[别run]` |
| x234 | {1:…,2:…,3:…} | ✗ | 疑 JNI 三时间戳 | 未 trace |
| x235 | 4966300 | ✗ | 疑 /proc/meminfo | 本 trace 无 meminfo 读；值反推 |
| x236 | 55558246400 | ✓ | 现场采集：statfs(/sdcard) | 专项：statfs 实锤 `[别run]` |
| x237 | 55558246400 | ✓ | 现场采集：statfs(可用) | 同 statfs `[别run]` |
| x238 | cn | ✗ | 疑 JNI Locale.getCountry | 未 trace |
| x242 | [] | ✗ | 空列表 | 无 |
| x243 | 1782285462475 | ✓ | 现场采集：clock_gettime(REALTIME) | 采集时刻组,同 x44 机制(realtime→ms,so 0x29c034)。4 次 realtime 读之一 |
| x247 | {0:72.7,…,5:47.1} | ✗ | 疑 JNI 6 浮点指标 | 未 trace |
| x258 | 0 | ✗ | 布尔标志 | 未 taint |
| x259 | 0 | ✗ | 布尔标志 | 未 taint |
| x260 | 1782285462973 | ✓ | 现场采集：clock_gettime(REALTIME) | 采集时刻组,同 x44 机制。与 x44 同值(同一采集瞬间读) |
| x261 | 1 | ✗ | 布尔标志 | 未 taint |
| x263 | 0 | ✗ | 布尔标志 | 未 taint |
| x264 | 0 | ✗ | 布尔标志 | 未 taint |
| x267 | 0 | ✗ | 布尔标志 | 未 taint |
| x269 | 1230768000000 | ✗ | 疑 2009 兜底常量 | 未证 |
| x272 | 0 | ✗ | 布尔标志 | 未 taint |
| x285 | 0 | ✗ | 布尔标志 | 未 taint |
| x286 | EAACAAgAAgDV0vfL…vZFgmlB | ✓ | 搬运(已实锤)：从存储/资源 memcpy，非现场采集 | 专项：@seq822704(memcpy so 0x4fd438)，原样搬入 |
| x289 | 1782285463009 | ✓ | 现场采集：clock_gettime(REALTIME) | 采集时刻组,同 x44 机制。采集末尾读(值最大,1782285463009) |
| x290 | -1 | ✗ | 不可用码 | 无 |
| x293 | 14696431 | ✗ | 大数值 | 未 taint |
| x296 | "" | ✗ | 空/占位 | 无 |
| x301 | ABSENT,ABSENT | ✓ | 属性：gsm.sim.state | 本会话实锤：`__system_property_find("gsm.sim.state")` @seq711577 |
| x302 | "" | ✗ | 疑 JNI 运营商 | 未 trace |
| x303 | "" | ✗ | 疑 JNI IMSI | 未 trace |
| x304 | 2 | ✗ | 小枚举/计数 | 未 taint |
| x305 | -3 | ✗ | 错误码 | 无 |

### 统计（口径：✓ = 有实锤，含现场采集 + 已实锤搬运；共 67 个 ✓）
> ⚠️ **J 族数值标志 = Settings 查询（已实锤 3 例，跨 System/Secure/Global）**：
> - x31 = `Settings.System.getInt("screen_brightness")` — 屏幕亮度
> - x37 = `Settings.Secure.getInt("accessibility_enabled")` — 无障碍开关(**反自动化**)
> - x38 = `Settings.Global.getInt("adb_enabled")` — ADB 调试(**反调试**,值1=开)
>
> ⇒ J 族(x40/x43/x45/x70/x76/x93/x267…)是一批 **`Settings.getInt/getString` 查询**,含大量反检测项(ADB/无障碍/开发者选项等),**不是"内部计数/枚举"**。采集点 `tag=5` 是内部 Value 的 i32 类型标签,非 serde 判别式。**固定追法**:Frida 采集点 → trace `NewStringUTF` 设置名 → `sub_4BEA18` CallStaticIntMethodV(env+0x410) 返回值。⚠️ doc 早期 x39=ADB_ENABLED 猜测错误,ADB 实为 x38。
- **✓ 有实锤·现场采集（46 个）**：
  - **系统属性(20,`sub_138D58` 解密名+查属性区,内存实锤)**：x7, x9, x10, x11, x12, x13, x14, x15, x16, x17, x18, x19, x20, x21, x22, x23, x24, x25, x29、**x39(`sys.usb.state`="adb",USB模式,反调试)**；另 x69/x155(序列号扫描)、x301(gsm.sim.state)。
  - **syscall**：uname x26/27/28、getpid x79、openat x47/x110、statfs x231/232/236/237、fstatat x165/x189、sysfs x68、clock_gettime 开机时刻 x6、clock_gettime(REALTIME) 采集时刻 x44/x243/x260/x289。
  - **本地计算**：CRC32 x99、MD5 x137、派生 x173；**运行期生成** UUID x174/x180；**JNI 现场取值** ANDROID_ID x171、**Settings.getInt 查询 x31(亮度)/x37(无障碍,反自动化)/x38(adb_enabled,反调试)**、**x40=TelephonyManager.getSimState()=1(无卡)**。
- **✓ 有实锤·搬运（16 个）**：x0, x1, x2, x3, x4, x8, x49（PackageInfo/ApplicationInfo 字段）、x5（渠道名,app 配置对象）、x30（DisplayMetrics 屏幕串,配置 map）、x46, x134（存储 ID）、x85, x86, x111, x145（Java 摘要 JNI 回传）、x286（存储 token）。搬运链完整实锤,值在 Java/init/存储侧产生,libtiny 只 JNI 读/克隆/序列化。
- **✗ 无实锤（其余全部）**：JNI 类(x123 UA,x238 Locale,x247 浮点指标…)、事件时间戳(x72/x73/x87 待追)、J 族数值标志(x40/x43/x45/x93/x267…疑 Settings 查询,同 x31/x37/x38 追法)、条件性摘要(x146/x185)。

---

## Java 字段来源表（IDA 明文实锤：libtiny JNI 反射读取的 Android 对象字段）

libtiny 通过 JNI `FindClass`+`GetFieldID`+`GetObjectField/GetIntField/GetLongField` 从 app 传入的两个 Android 对象逐字段读取，缓存进全局 `0x746c08`。字段名/签名均为 IDA 反编译明文。

### `android.content.pm.PackageInfo`（解析器 `sub_4BC564`，读取 `sub_2BFF48`）
| Java 字段 | 签名 | fieldID | JNI 读法 | 映射 x |
|---|---|---|---|---|
| `packageName` | Ljava/lang/String; | qword_74EF88 | GetObjectField+GetStringUTFChars | **x0** |
| `versionName` | Ljava/lang/String; | qword_74EF90 | 同上 | **x1** |
| `versionCode` | I | qword_74EFA8 | GetIntField | **x2** |
| `firstInstallTime` | J | qword_74EF98 | GetLongField | **x8** |
| `lastUpdateTime` | J | qword_74EFA0 | GetLongField | **x3 / x4**（读一次填两键;trace 实锤缓存克隆 seq52147-50） |
| `applicationInfo` | Landroid/content/pm/ApplicationInfo; | qword_74EFB0 | GetObjectField→子对象 | ↓ |

### `android.content.pm.ApplicationInfo`（解析器 `sub_4BE6C4`）
| Java 字段 | 签名 | fieldID | 映射 x / 备注 |
|---|---|---|---|
| `sourceDir` | Ljava/lang/String; | qword_74F108 | **x49**（/data/app/…/base.apk） |
| `publicSourceDir` | Ljava/lang/String; | qword_74F110 | 同 APK 路径类 |
| `dataDir` | Ljava/lang/String; | qword_74F118 | /data/user/0/com.xingin.xhs |
| `nativeLibraryDir` | Ljava/lang/String; | qword_74F120 | /data/app/…/lib/arm64 |
| `flags` | I | qword_74F0F8 | 应用 flags |
| `targetSdkVersion` | I | qword_74F100 | targetSdk |
| `labelRes` | I | qword_74F128 | — |
| `writeToParcel` | (Landroid/os/Parcel;I)V | qword_74F130 | GetMethodID（非字段） |

> ⇒ app 侧 `PackageManager.getPackageInfo(pkg, GET_...)` 得到 PackageInfo(含 applicationInfo) 传给 libtiny；libtiny **不自采**，纯 JNI 反射读字段。故 x0/x1/x2/x8/x49 等一组为 **搬运(源在 Java 层)**。
> **实锤三方**：字段名/类名=IDA 明文(`sub_4BC564`/`sub_4BE6C4`)；JNI 调用序列=trace(0x29c660 单函数 run,seq3873 GetObjectField/seq3887 GetStringUTFChars)；写缓存=Frida(`sub_29C660` X8+写前后)。

> 口径说明：✓ = 证据链完整（现场采集 或 已实锤搬运，看采集方式列区分）；✗ = 纯值语义猜测、无 trace/IDA 支撑。要把 ✗ 升 ✓ 需 taint 写入点 / 找到对应 syscall·属性读 / IDA 明文字段（如本组 PackageInfo 字段就是靠 IDA 明文 + trace + Frida 升上来的）。
