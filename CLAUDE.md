# Launch - Android 设备环境检测与指纹采集项目

## 作者信息
- **作者**: 在座的各位所有大佬
- **微信**: xx1193776794
- **项目**: Launch 设备环境检测

## 项目说明
收集全网特征检测，欢迎各位大佬提供，本app无混淆加密，可以查看各种检测点进行对抗

---

## 项目概述
这是一个 Android 安全检测项目，主要功能包括：
- 设备环境检测（安全检测）
- 设备指纹采集
- 设备信息获取

## 项目结构
```
app/src/main/
├── java/com/xff/launch/     # Java 层代码
│   └── MainActivity.java    # 主入口
└── cpp/                     # Native C++ 层代码
    ├── native-lib.cpp       # JNI 接口
    └── CMakeLists.txt       # CMake 配置
```

---

## UI 设计

### 整体布局架构
```
┌─────────────────────────────────────────────────────────────┐
│                        状态栏 (Status Bar)                   │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────┐   │
│  │                    顶部标题栏                         │   │
│  │  ┌──────┐                              ┌──────────┐ │   │
│  │  │ Logo │  Launch 设备检测              │ 刷新按钮 │ │   │
│  │  └──────┘                              └──────────┘ │   │
│  └─────────────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────┐   │
│  │                   检测状态概览卡片                     │   │
│  │  ┌─────────┐  ┌─────────┐  ┌─────────┐             │   │
│  │  │ 安全: 12│  │ 风险: 3 │  │ 未知: 2 │  总分: 85  │   │
│  │  └─────────┘  └─────────┘  └─────────┘             │   │
│  └─────────────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│                      内容区域 (Fragment)                     │
│                                                             │
│                    根据底部导航切换显示                       │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│  ┌───────────────┬───────────────┬───────────────┐         │
│  │   环境检测    │   指纹信息    │   机型信息    │         │
│  │      🛡️       │      🔐       │      📱       │         │
│  └───────────────┴───────────────┴───────────────┘         │
│                      底部导航栏                              │
└─────────────────────────────────────────────────────────────┘
```

### 配色方案
| 元素 | 颜色 | 色值 |
|-----|------|------|
| 主题色 | 科技蓝 | #2196F3 |
| 安全状态 | 绿色 | #4CAF50 |
| 风险状态 | 红色 | #F44336 |
| 警告状态 | 橙色 | #FF9800 |
| 未知状态 | 灰色 | #9E9E9E |
| 背景色 | 浅灰 | #F5F5F5 |
| 卡片背景 | 白色 | #FFFFFF |

---

### 板块一：设备环境检测

#### 界面布局
```
┌─────────────────────────────────────────────────────────────┐
│  ┌─────────────────────────────────────────────────────┐   │
│  │  检测状态总览                         [刷新检测 🔄]  │   │
│  │  ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐       │   │
│  │  │ 🟢 12  │ │ 🔴 3   │ │ 🟡 1   │ │ ⚪ 2   │       │   │
│  │  │ 安全   │ │ 风险   │ │ 警告   │ │ 未知   │       │   │
│  │  └────────┘ └────────┘ └────────┘ └────────┘       │   │
│  │                                                     │   │
│  │  综合评分: 72/100                    [中等风险]     │   │
│  │  ████████████████░░░░░░░░                          │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  🔓 Root 检测                              [展开 ▼] │   │
│  ├─────────────────────────────────────────────────────┤   │
│  │  ├─ 🔴 Magisk 检测          已检测到 Magisk        │   │
│  │  ├─ 🔴 SU 文件检测          /system/bin/su 存在    │   │
│  │  ├─ 🟢 KernelSU 检测        未检测到               │   │
│  │  ├─ 🟢 APatch 检测          未检测到               │   │
│  │  └─ 🔴 Root 管理器          检测到 Magisk Manager  │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  🎣 Hook 检测                              [展开 ▼] │   │
│  ├─────────────────────────────────────────────────────┤   │
│  │  ├─ 🟢 Xposed 框架          未检测到               │   │
│  │  ├─ 🟢 Frida 检测           未检测到               │   │
│  │  ├─ 🟢 LSPosed 检测         未检测到               │   │
│  │  └─ 🟢 内存完整性           正常                   │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  📱 模拟器检测                             [展开 ▼] │   │
│  ├─────────────────────────────────────────────────────┤   │
│  │  ├─ 🟢 模拟器环境           真实设备               │   │
│  │  ├─ 🟢 虚拟机特征           未检测到               │   │
│  │  └─ 🟢 多开检测             未检测到               │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  🔍 调试检测                               [展开 ▼] │   │
│  ├─────────────────────────────────────────────────────┤   │
│  │  ├─ 🟡 USB 调试             已开启                 │   │
│  │  ├─ 🟢 调试器连接           未连接                 │   │
│  │  └─ 🟢 JDWP 检测            未检测到               │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  🌐 网络环境检测                           [展开 ▼] │   │
│  ├─────────────────────────────────────────────────────┤   │
│  │  ├─ 🟢 VPN 状态             未连接                 │   │
│  │  ├─ 🟢 代理设置             未设置                 │   │
│  │  └─ 🟢 抓包检测             未检测到               │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

#### 检测项状态图标
| 状态 | 图标 | 颜色 | 说明 |
|-----|------|------|------|
| 安全 | 🟢 ✓ | #4CAF50 | 检测通过，无风险 |
| 风险 | 🔴 ✗ | #F44336 | 检测到风险项 |
| 警告 | 🟡 ⚠ | #FF9800 | 存在潜在风险 |
| 未知 | ⚪ ? | #9E9E9E | 无法确定状态 |

#### 检测分类详情
| 分类 | 图标 | 检测项 |
|-----|------|--------|
| Root 检测 | 🔓 | Magisk、KernelSU、APatch、SukiSU、SuperSU、su文件 |
| Hook 检测 | 🎣 | Xposed、Frida、LSPosed、EdXposed、Substrate |
| 模拟器检测 | 📱 | 模拟器环境、虚拟机、多开、云手机 |
| 调试检测 | 🔍 | USB调试、调试器、JDWP、ptrace |
| 完整性检测 | 🛡️ | 签名校验、DEX校验、SO校验、CRC校验 |
| 网络检测 | 🌐 | VPN、代理、抓包工具 |

---

### 板块二：设备指纹信息

#### 界面布局
```
┌─────────────────────────────────────────────────────────────┐
│  ┌─────────────────────────────────────────────────────┐   │
│  │  设备指纹概览                         [刷新 🔄] [复制]│   │
│  │                                                     │   │
│  │  ┌─────────────────────────────────────────────┐   │   │
│  │  │         综合设备指纹 (Device ID)             │   │   │
│  │  │  a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6          │   │   │
│  │  │                                             │   │   │
│  │  │  可信度: 95%  ████████████████████░        │   │   │
│  │  │  状态: 🟢 未检测到篡改                       │   │   │
│  │  └─────────────────────────────────────────────┘   │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  📋 设备标识符                                      │   │
│  ├─────────────────────────────────────────────────────┤   │
│  │                                                     │   │
│  │  ANDROID_ID                                        │   │
│  │  ┌─────────────────────────────────────────────┐   │   │
│  │  │ 9a8b7c6d5e4f3a2b                    [复制]  │   │   │
│  │  │ Java: 9a8b...  Native: 9a8b...  🟢 一致    │   │   │
│  │  └─────────────────────────────────────────────┘   │   │
│  │                                                     │   │
│  │  设备序列号 (Serial)                               │   │
│  │  ┌─────────────────────────────────────────────┐   │   │
│  │  │ ABC123DEF456                        [复制]  │   │   │
│  │  │ Java: ABC1...  Native: ABC1...  🟢 一致    │   │   │
│  │  └─────────────────────────────────────────────┘   │   │
│  │                                                     │   │
│  │  MAC 地址                                          │   │
│  │  ┌─────────────────────────────────────────────┐   │   │
│  │  │ 00:11:22:33:44:55                   [复制]  │   │   │
│  │  │ Java: 00:11...  Native: 00:11...  🟢 一致  │   │   │
│  │  └─────────────────────────────────────────────┘   │   │
│  │                                                     │   │
│  │  IMEI (需要权限)                                   │   │
│  │  ┌─────────────────────────────────────────────┐   │   │
│  │  │ 未授权访问                         [申请权限] │   │   │
│  │  └─────────────────────────────────────────────┘   │   │
│  │                                                     │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  🔐 指纹哈希                                        │   │
│  ├─────────────────────────────────────────────────────┤   │
│  │                                                     │   │
│  │  硬件指纹 Hash                                      │   │
│  │  ┌─────────────────────────────────────────────┐   │   │
│  │  │ SHA256: 4a7d8f...9c2e1b              [复制] │   │   │
│  │  └─────────────────────────────────────────────┘   │   │
│  │                                                     │   │
│  │  软件指纹 Hash                                      │   │
│  │  ┌─────────────────────────────────────────────┐   │   │
│  │  │ SHA256: 1b3c5d...7e9f0a              [复制] │   │   │
│  │  └─────────────────────────────────────────────┘   │   │
│  │                                                     │   │
│  │  Build 指纹                                        │   │
│  │  ┌─────────────────────────────────────────────┐   │   │
│  │  │ Xiaomi/sheng/sheng:14/UKQ1.230804.001/...  │   │   │
│  │  │                                     [复制] │   │   │
│  │  └─────────────────────────────────────────────┘   │   │
│  │                                                     │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  ⚖️ 多源比对结果                                    │   │
│  ├─────────────────────────────────────────────────────┤   │
│  │  │ 检测项     │ Java  │ Native │ Syscall │ 状态 │   │   │
│  │  ├────────────┼───────┼────────┼─────────┼──────┤   │   │
│  │  │ ANDROID_ID │ 9a8b..│ 9a8b.. │ 9a8b..  │ 🟢   │   │   │
│  │  │ Serial     │ ABC1..│ ABC1.. │ ABC1..  │ 🟢   │   │   │
│  │  │ Build.MODEL│ Mi 14 │ Mi 14  │ Mi 14   │ 🟢   │   │   │
│  │  │ MAC        │ 00:11.│ 00:11. │ 00:11.  │ 🟢   │   │   │
│  │  └────────────┴───────┴────────┴─────────┴──────┘   │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

### 板块三：设备机型信息

#### 界面布局
```
┌─────────────────────────────────────────────────────────────┐
│  ┌─────────────────────────────────────────────────────┐   │
│  │  机型合法性检测                       [刷新检测 🔄]  │   │
│  │                                                     │   │
│  │  ┌─────────────────────────────────────────────┐   │   │
│  │  │  机型评分: 95/100              [正常 🟢]    │   │   │
│  │  │  █████████████████████████████████████░░░░  │   │   │
│  │  │                                             │   │   │
│  │  │  Build一致性 ✓  ROM匹配 ✓  服务匹配 ✓      │   │   │
│  │  │  硬件一致 ✓     指纹格式 ✓                  │   │   │
│  │  └─────────────────────────────────────────────┘   │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  📱 基础信息                                        │   │
│  ├─────────────────────────────────────────────────────┤   │
│  │  品牌          Xiaomi                              │   │
│  │  型号          Mi 14                               │   │
│  │  制造商        Xiaomi                              │   │
│  │  设备代号      sheng                               │   │
│  │  主板          kalama                              │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  ⚙️ 系统信息                                        │   │
│  ├─────────────────────────────────────────────────────┤   │
│  │  Android 版本   14                                  │   │
│  │  API Level      34                                 │   │
│  │  ROM 版本       MIUI V14.0.5                       │   │
│  │  安全补丁       2024-01-01                         │   │
│  │  内核版本       5.15.78-android14-...              │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  🔧 硬件信息                                        │   │
│  ├─────────────────────────────────────────────────────┤   │
│  │  CPU            Snapdragon 8 Gen 3 (8核)           │   │
│  │  GPU            Adreno 750                         │   │
│  │  内存           12 GB                               │   │
│  │  存储           256 GB (可用 180 GB)               │   │
│  │  屏幕           1440x3200 @ 460 dpi                │   │
│  │  摄像头         4 (后置3 + 前置1)                  │   │
│  │  传感器         15 个                              │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  🌐 网络信息                                        │   │
│  ├─────────────────────────────────────────────────────┤   │
│  │  网络类型       WiFi                                │   │
│  │  WiFi SSID      MyNetwork                          │   │
│  │  IP 地址        192.168.1.100                      │   │
│  │  运营商         中国移动                            │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  ✅ 厂商服务检测                                    │   │
│  ├─────────────────────────────────────────────────────┤   │
│  │  小米服务       🟢 已安装 (com.xiaomi.account)     │   │
│  │  小米推送       🟢 已安装 (com.xiaomi.xmsf)        │   │
│  │  GMS 服务       🟢 已安装                          │   │
│  │  HMS 服务       ⚪ 未安装 (正常-小米设备)          │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  📋 ROM 特征验证                                    │   │
│  ├─────────────────────────────────────────────────────┤   │
│  │  ro.miui.ui.version.name    🟢 V14 (符合小米)      │   │
│  │  ro.build.version.emui      ⚪ 无 (正常)           │   │
│  │  ro.build.version.opporom   ⚪ 无 (正常)           │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

### 刷新检测功能

#### 功能说明
```
┌─────────────────────────────────────────────────────────────┐
│                      刷新检测功能                            │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  触发方式:                                                  │
│  1. 顶部标题栏刷新按钮 - 刷新当前页面                        │
│  2. 下拉刷新 (SwipeRefreshLayout) - 刷新当前页面            │
│  3. 检测状态卡片刷新按钮 - 刷新全部检测                      │
│                                                             │
│  刷新流程:                                                  │
│  ┌────────┐    ┌────────┐    ┌────────┐    ┌────────┐     │
│  │ 点击   │ -> │ 显示   │ -> │ 执行   │ -> │ 更新   │     │
│  │ 刷新   │    │ Loading│    │ 检测   │    │ UI     │     │
│  └────────┘    └────────┘    └────────┘    └────────┘     │
│                                                             │
│  刷新状态:                                                  │
│  • 刷新中: 显示 ProgressBar + "正在检测..."                 │
│  • 刷新完成: Toast "检测完成" + 更新时间戳                   │
│  • 刷新失败: Toast "检测失败，请重试"                        │
│                                                             │
│  最后检测时间:                                               │
│  显示格式: "上次检测: 2024-01-15 14:30:25"                  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

#### 刷新按钮设计
```xml
<!-- 顶部刷新按钮 -->
<ImageButton
    android:id="@+id/btn_refresh"
    android:layout_width="48dp"
    android:layout_height="48dp"
    android:src="@drawable/ic_refresh"
    android:background="?attr/selectableItemBackgroundBorderless"
    android:contentDescription="刷新检测" />

<!-- 刷新动画: 点击后旋转 -->
```

---

### 关于页面 / 作者信息

#### 界面布局
```
┌─────────────────────────────────────────────────────────────┐
│                        关于                                  │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│                    ┌──────────────┐                         │
│                    │     LOGO     │                         │
│                    │    Launch    │                         │
│                    └──────────────┘                         │
│                                                             │
│                   Launch 设备检测                           │
│                     版本 1.0.0                              │
│                                                             │
│  ─────────────────────────────────────────────────────────  │
│                                                             │
│                      作者信息                               │
│                                                             │
│           👤 作者: 在座的各位所有大佬                                   │
│           📧 邮箱: 1193776794@qq.com                        │
│                                                             │
│  ─────────────────────────────────────────────────────────  │
│                                                             │
│                      功能介绍                               │
│                                                             │
│   • 设备环境安全检测 (Root/Hook/模拟器/调试)                │
│   • 设备指纹采集与篡改检测                                  │
│   • 机型合法性验证                                          │
│   • 多层检测架构 (Java/Native/Syscall)                      │
│                                                             │
│  ─────────────────────────────────────────────────────────  │
│                                                             │
│         [检查更新]        [反馈问题]        [评分]          │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

### UI 组件规划
```
app/src/main/
├── java/com/xff/launch/
│   ├── MainActivity.java              # 主页面（底部导航容器）
│   ├── ui/
│   │   ├── environment/
│   │   │   ├── EnvironmentFragment    # 环境检测页面
│   │   │   └── EnvironmentViewModel   # 环境检测数据
│   │   ├── fingerprint/
│   │   │   ├── FingerprintFragment    # 指纹信息页面
│   │   │   └── FingerprintViewModel   # 指纹信息数据
│   │   ├── deviceinfo/
│   │   │   ├── DeviceInfoFragment     # 机型信息页面
│   │   │   └── DeviceInfoViewModel    # 机型信息数据
│   │   └── about/
│   │       └── AboutFragment          # 关于页面
│   ├── adapter/
│   │   ├── DetectionAdapter           # 检测结果列表适配器
│   │   ├── DetectionGroupAdapter      # 检测分组适配器 (可展开)
│   │   └── FingerprintAdapter         # 指纹信息适配器
│   ├── model/
│   │   ├── DetectionItem              # 检测项数据模型
│   │   ├── DetectionGroup             # 检测分组模型
│   │   ├── FingerprintItem            # 指纹项数据模型
│   │   └── DeviceInfo                 # 设备信息模型
│   ├── detector/
│   │   ├── RootDetector               # Root 检测器
│   │   ├── HookDetector               # Hook 检测器
│   │   ├── EmulatorDetector           # 模拟器检测器
│   │   ├── DebugDetector              # 调试检测器
│   │   └── IntegrityDetector          # 完整性检测器
│   └── utils/
│       ├── RefreshManager             # 刷新管理器
│       └── ClipboardHelper            # 复制工具
├── cpp/
│   ├── native-lib.cpp                 # JNI 入口
│   ├── detector/                      # Native 检测实现
│   └── syscall/                       # Syscall 直调实现
└── res/
    ├── layout/
    │   ├── activity_main.xml          # 主布局
    │   ├── fragment_environment.xml   # 环境检测布局
    │   ├── fragment_fingerprint.xml   # 指纹信息布局
    │   ├── fragment_device_info.xml   # 机型信息布局
    │   ├── fragment_about.xml         # 关于页面布局
    │   ├── item_detection.xml         # 检测项列表项
    │   ├── item_detection_group.xml   # 检测分组项
    │   ├── item_fingerprint.xml       # 指纹信息项
    │   └── layout_status_overview.xml # 状态概览卡片
    ├── drawable/
    │   ├── ic_refresh.xml             # 刷新图标
    │   ├── ic_status_safe.xml         # 安全图标
    │   ├── ic_status_risk.xml         # 风险图标
    │   ├── ic_status_warning.xml      # 警告图标
    │   └── ic_status_unknown.xml      # 未知图标
    ├── values/
    │   ├── colors.xml                 # 颜色定义
    │   ├── strings.xml                # 字符串资源
    │   └── themes.xml                 # 主题样式
    └── menu/
        └── bottom_navigation.xml      # 底部导航菜单
```

### 字符串资源 (strings.xml)
```xml
<!-- 应用信息 -->
<string name="app_name">Launch</string>
<string name="app_version">1.0.0</string>
<string name="author_name">在座的各位所有大佬</string>
<string name="author_email">1193776794@qq.com</string>

<!-- 导航标签 -->
<string name="nav_environment">环境检测</string>
<string name="nav_fingerprint">指纹信息</string>
<string name="nav_device_info">机型信息</string>

<!-- 状态文本 -->
<string name="status_safe">安全</string>
<string name="status_risk">风险</string>
<string name="status_warning">警告</string>
<string name="status_unknown">未知</string>

<!-- 刷新相关 -->
<string name="refresh">刷新检测</string>
<string name="refreshing">正在检测...</string>
<string name="refresh_complete">检测完成</string>
<string name="last_check_time">上次检测: %s</string>
```

## 功能模块

### 1. 设备环境检测 (Environment Detection)

> **核心原则**: 所有检测均采用多层获取架构，避免单一途径被 Hook 绕过

#### 1.0 多层检测架构 (Anti-Hook Detection Framework)

##### 1.0.1 三层检测体系
```
┌─────────────────────────────────────────────────────────────┐
│                     环境检测多层架构                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│   Layer 1: Java API 层                                      │
│   ├── PackageManager.getPackageInfo()                       │
│   ├── File.exists() / File.canRead()                        │
│   ├── Runtime.exec()                                        │
│   └── 易被 Xposed/LSPosed Hook                              │
│                                                             │
│   Layer 2: Native libc 层                                   │
│   ├── access() / stat() / fopen()                           │
│   ├── opendir() / readdir()                                 │
│   ├── __system_property_get()                               │
│   └── 可被 Frida PLT/GOT Hook                               │
│                                                             │
│   Layer 3: 直接 Syscall 层 (最可信)                          │
│   ├── SYS_faccessat - 文件存在检测                           │
│   ├── SYS_openat + SYS_read - 文件读取                       │
│   ├── SYS_getdents64 - 目录遍历                              │
│   ├── SYS_stat/fstat - 文件状态                              │
│   └── 绕过 libc，直接 SVC 中断                               │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

##### 1.0.2 文件检测多层实现

**Layer 1 - Java:**
```java
// 易被 Hook
boolean exists = new File("/system/bin/su").exists();
```

**Layer 2 - Native libc:**
```c
// 可被 PLT Hook
int ret = access("/system/bin/su", F_OK);
```

**Layer 3 - Direct Syscall (ARM64):**
```c
// 绕过 libc，最难 Hook
static inline int syscall_faccessat(const char *path) {
    register long x8 __asm__("x8") = __NR_faccessat;
    register long x0 __asm__("x0") = AT_FDCWD;
    register const char *x1 __asm__("x1") = path;
    register long x2 __asm__("x2") = F_OK;
    register long x3 __asm__("x3") = 0;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x3), "r"(x8) : "memory");
    return (int)x0;
}
```

**Layer 3 - Direct Syscall (ARM32):**
```c
static inline int syscall_faccessat_arm32(const char *path) {
    register long r7 __asm__("r7") = __NR_faccessat;
    register long r0 __asm__("r0") = AT_FDCWD;
    register const char *r1 __asm__("r1") = path;
    register long r2 __asm__("r2") = F_OK;
    register long r3 __asm__("r3") = 0;
    __asm__ volatile("svc #0" : "+r"(r0) : "r"(r1), "r"(r2), "r"(r3), "r"(r7) : "memory");
    return (int)r0;
}
```

##### 1.0.3 进程/线程检测多层实现

**Layer 1 - Java:**
```java
// 读取 /proc
BufferedReader br = new BufferedReader(new FileReader("/proc/self/maps"));
```

**Layer 2 - Native libc:**
```c
// 使用 libc
FILE *fp = fopen("/proc/self/maps", "r");
DIR *dir = opendir("/proc");
```

**Layer 3 - Direct Syscall:**
```c
// 直接系统调用读取 /proc
int fd = syscall(__NR_openat, AT_FDCWD, "/proc/self/maps", O_RDONLY);
char buf[4096];
syscall(__NR_read, fd, buf, sizeof(buf));
syscall(__NR_close, fd);

// 直接系统调用遍历目录
int dfd = syscall(__NR_openat, AT_FDCWD, "/proc", O_RDONLY | O_DIRECTORY);
char dirbuf[1024];
syscall(__NR_getdents64, dfd, dirbuf, sizeof(dirbuf));
```

##### 1.0.4 包名检测多层实现

**Layer 1 - Java:**
```java
// PackageManager 检测已安装应用
PackageManager pm = context.getPackageManager();
pm.getPackageInfo("com.topjohnwu.magisk", 0);
```

**Layer 2 - Native:**
```c
// 检测 /data/data/包名 目录
access("/data/data/com.topjohnwu.magisk", F_OK);
```

**Layer 3 - Syscall:**
```c
// 直接 syscall 检测
syscall(__NR_faccessat, AT_FDCWD, "/data/data/com.topjohnwu.magisk", F_OK, 0);
```

##### 1.0.5 属性检测多层实现

**Layer 1 - Java:**
```java
// System Properties
String value = System.getProperty("ro.build.tags");
// 或通过反射调用 SystemProperties
```

**Layer 2 - Native libc:**
```c
// __system_property_get
char value[PROP_VALUE_MAX];
__system_property_get("ro.build.tags", value);
```

**Layer 3 - Direct Read:**
```c
// 直接读取 /system/build.prop 或 /vendor/build.prop
// 通过 syscall 读取文件内容解析属性
int fd = syscall(__NR_openat, AT_FDCWD, "/system/build.prop", O_RDONLY);
```

##### 1.0.6 端口检测多层实现

**Layer 1 - Java:**
```java
// Socket 连接测试
Socket socket = new Socket();
socket.connect(new InetSocketAddress("127.0.0.1", 27042), 100);
```

**Layer 2 - Native libc:**
```c
// 读取 /proc/net/tcp
FILE *fp = fopen("/proc/net/tcp", "r");
// 或使用 connect()
```

**Layer 3 - Syscall:**
```c
// 直接 syscall 读取
syscall(__NR_openat, AT_FDCWD, "/proc/net/tcp", O_RDONLY);
// 或直接 syscall connect
syscall(__NR_socket, AF_INET, SOCK_STREAM, 0);
syscall(__NR_connect, sockfd, &addr, sizeof(addr));
```

##### 1.0.7 检测结果融合策略
```
┌────────────────────────────────────────────────────────────┐
│                    检测结果融合引擎                          │
├────────────────────────────────────────────────────────────┤
│                                                            │
│   三层检测结果:                                             │
│   ┌─────────┬─────────┬─────────┬────────────────────┐    │
│   │ Java    │ Native  │ Syscall │ 判定结果           │    │
│   ├─────────┼─────────┼─────────┼────────────────────┤    │
│   │ 检出    │ 检出    │ 检出    │ ✓ 确认存在风险     │    │
│   │ 未检出  │ 检出    │ 检出    │ ⚠ Java层被Hook     │    │
│   │ 未检出  │ 未检出  │ 检出    │ ⚠ libc层被Hook     │    │
│   │ 检出    │ 未检出  │ 未检出  │ ? 误报/需复查      │    │
│   │ 未检出  │ 未检出  │ 未检出  │ ✓ 环境安全         │    │
│   └─────────┴─────────┴─────────┴────────────────────┘    │
│                                                            │
│   原则: Syscall 层结果优先级最高                            │
│                                                            │
└────────────────────────────────────────────────────────────┘
```

---

#### 1.1 Root 检测 (Root Detection)

> 每项检测均需实现 Java/Native/Syscall 三层

##### 1.1.1 文件路径检测
- [ ] 检测 su 二进制文件路径
  - /system/bin/su
  - /system/xbin/su
  - /sbin/su
  - /data/local/su
  - /data/local/bin/su
  - /data/local/xbin/su
  - /system/sd/xbin/su
  - /system/bin/failsafe/su
  - /vendor/bin/su
- [ ] 检测 busybox
  - /system/xbin/busybox
  - /system/bin/busybox

##### 1.1.2 Root 管理器检测
- [ ] 检测已安装的 Root 管理应用
  - com.noshufou.android.su (Superuser)
  - com.koushikdutta.superuser
  - eu.chainfire.supersu (SuperSU)
  - com.kingroot.kinguser
  - com.kingo.root
  - com.topjohnwu.magisk (Magisk Manager)
  - me.phh.superuser
  - com.oasisfeng.greenify

##### 1.1.3 Magisk 检测
- [ ] 检测 Magisk 相关文件
  - /sbin/.magisk
  - /data/adb/magisk
  - /data/adb/magisk.img
  - /data/adb/magisk.db
  - /cache/magisk.log
  - /cache/.disable_magisk
  - /dev/.magisk.unblock
  - /data/adb/modules
- [ ] 检测 /proc/self/mountinfo 中的 "magisk" 字符串
- [ ] 检测 Zygisk 特征（mountinfo 包含 "zygote"）
- [ ] 检测 MagiskHide / Shamiko 隐藏模块
- [ ] Mount namespace 不一致检测
- [ ] PID namespace 不一致检测
- [ ] Magic Mount 挂载数量异常检测
- [ ] 检测 tmpfs & bind mounts 注入

##### 1.1.4 KernelSU 检测 (2024-2025 新型)
- [ ] 文件路径检测
  - /data/adb/ksu
  - /data/adb/ksud
  - /data/adb/ksu/bin/busybox
  - /data/adb/ksu/bin/resetprop
- [ ] 包名检测
  - me.weishu.kernelsu (KernelSU Manager)
- [ ] 内核特征检测
  - 检测 /proc/kallsyms 中的 ksu 符号
  - 检测内核版本字符串中的 KernelSU 标识
- [ ] 系统调用 Hook 检测
  - 检测 syscall table 是否被修改
- [ ] OverlayFS 挂载检测
  - 检测异常的 overlay 文件系统挂载

##### 1.1.5 APatch 检测 (2024-2025 新型)
- [ ] 文件路径检测
  - /data/adb/ap
  - /data/adb/apd
  - /data/adb/ap/bin
- [ ] 包名检测
  - me.bmax.apatch (APatch Manager)
- [ ] SuperKey 机制检测
  - APatch 使用 SuperKey 而非传统 su
- [ ] 内核补丁检测
  - 检测 boot.img 内核是否被修改
- [ ] KPM (Kernel Patch Module) 检测
  - 检测内核模块加载痕迹

##### 1.1.6 SukiSU / SukiSU Ultra 检测 (2025 最新)
- [ ] 文件路径检测
  - /data/adb/ksu (继承自 KernelSU)
  - /data/adb/sukisu
- [ ] 包名检测
  - org.sukisu.manager
- [ ] SUSFS 特征检测 (重点)
  - SUSFS 是内核级隐藏框架
  - 检测 /proc/filesystems 中的 susfs
  - 检测 sus_su 路径隐藏机制
  - 检测 add_sus_mount 隐藏的挂载点
- [ ] VFS Hooks 检测
  - 检测虚拟文件系统钩子
- [ ] 内核级属性伪装检测
  - ro.boot.verifiedbootstate 被伪装为 "green"
  - ro.boot.vbmeta.device_state 被伪装为 "locked"
  - sys.oem_unlock_allowed 被伪装为 "0"

##### 1.1.7 Zygisk 变体检测
- [ ] Zygisk Next 检测
  - 替代原生 Magisk Zygisk
  - 检测 /data/adb/modules/zygiskNext
- [ ] ReZygisk 检测 (2024-2025 新型 - 开源Zygisk实现)
  - **文件路径检测**
    - /data/adb/modules/rezygisk (模块目录)
    - /data/adb/modules/rezygisk/module.prop (模块配置)
    - /data/adb/modules/rezygisk/zygisk (Zygisk标识文件)
  - **进程特征检测**
    - zygiskd 守护进程 (32/64位)
    - 检测 /proc 中的 zygiskd 进程
  - **内存映射检测**
    - /proc/self/maps 中的 rezygisk 相关库
    - LSPLt 库特征 (PLT Hook库)
    - CSOLoader 库特征 (自定义链接器)
  - **模块描述特征**
    - 包含 "ReZygisk" 字符串
    - 包含 "[Monitor: ✅, ReZygisk 64-bit: ✅, ReZygisk 32-bit: ✅]" 状态指示器
  - **兼容性特征**
    - 同时支持 Magisk/KernelSU/APatch
    - 纯C语言实现，开源 (AGPL 3.0/GPL)
  - **与 Zygisk Next 的区别**
    - 完全开源 vs 闭源
    - 纯C实现 vs 混合语言
    - 可审计代码 vs 不透明
- [ ] LSPosed 注入检测
  - 检测进程中的 lspd 痕迹

##### 1.1.8 Root 隐藏模块检测
- [ ] Shamiko 检测
  - 检测 /data/adb/modules/shamiko
  - 白名单模式下的进程行为异常
- [ ] Zygisk-Assistant 检测
  - 检测 /data/adb/modules/zygisk-assistant
- [ ] HideMyApplist 检测
  - 应用列表隐藏行为检测
- [ ] PlayIntegrityFix 检测
  - 检测 /data/adb/modules/playintegrityfix
- [ ] TrickyStore 检测
  - keybox 伪造检测
  - 证书欺骗检测

##### 1.1.9 内核级 Root 通用检测
- [ ] SELinux 上下文检测
  - 检测 u:r:su:s0 上下文
  - 检测 u:r:magisk:s0 上下文
- [ ] 进程属性检测
  - 检测异常的 ro.debuggable
  - 检测异常的 ro.secure
- [ ] /proc 信息一致性检测
  - /proc/self/mountinfo 分析
  - /proc/self/maps 分析
  - /proc/mounts 挂载点数量分析
- [ ] Loop 设备检测
  - 检测 /proc/fs/jbd2/loop* 是否被隐藏
  - 检测 /proc/fs/ext4/ 异常
- [ ] 厂商 Sepolicy 检测
  - 检测 sepolicy 是否被修改
  - 检测 "lineage" 等自定义 ROM 痕迹

##### 1.1.10 系统属性检测
- [ ] 检测 ro.build.tags 是否为 "test-keys"
- [ ] 检测 ro.debuggable 属性
- [ ] 检测 ro.secure 属性
- [ ] 检测 ro.build.selinux 属性
- [ ] 检测 ro.boot.verifiedbootstate
- [ ] 检测 ro.boot.flash.locked
- [ ] 检测 ro.boot.vbmeta.device_state

##### 1.1.11 权限位检测
- [ ] 检测系统目录写权限
  - /system 是否可写
  - /system/app 是否可写
  - /system/bin 是否可写
  - /vendor 是否可写
- [ ] 检测私有目录访问权限
  - /data 目录访问测试
  - /data/data 目录访问测试

##### 1.1.12 命令执行检测
- [ ] 尝试执行 su 命令
- [ ] 尝试执行 which su
- [ ] 检测 PATH 环境变量中的 su
- [ ] 检测 ksud 命令 (KernelSU)
- [ ] 检测 apd 命令 (APatch)

---

#### 1.2 Hook 框架检测 (Hook Detection)

##### 1.2.1 Xposed 框架检测
- [ ] 文件检测
  - /system/framework/XposedBridge.jar
  - /system/lib/libxposed_art.so
  - /system/lib64/libxposed_art.so
  - /system/xposed.prop
  - /data/data/de.robv.android.xposed.installer
- [ ] 包名检测
  - de.robv.android.xposed.installer
  - de.robv.android.xposed
- [ ] 类加载检测
  - 检测 ClassLoader 中是否存在 XposedBridge 类
- [ ] 堆栈检测
  - 检测调用堆栈中的 Xposed 相关类
- [ ] 内存特征检测
  - 检测内存中 "XposedBridge" 字符串
  - 检测 /proc/self/maps 中的 xposed 特征

##### 1.2.2 LSPosed / EdXposed 检测
- [ ] 文件检测
  - /data/adb/lspd
  - /data/adb/edxp
- [ ] 包名检测
  - org.lsposed.manager
  - org.meowcat.edxposed.manager

##### 1.2.3 Frida 检测 (重点)
- [ ] 进程检测
  - 检测 frida-server 进程名
  - 检测 frida-helper 进程
  - 遍历 /proc 检测可疑进程
- [ ] 端口检测
  - 检测默认端口 27042
  - 检测 27043 端口
  - 遍历 /proc/net/tcp 检测监听端口
- [ ] D-Bus 协议检测
  - 向所有端口发送 D-Bus AUTH 消息
  - 检测 "REJECT" 响应特征
- [ ] 文件检测
  - /data/local/tmp/frida-server
  - /data/local/tmp/re.frida.server
- [ ] 内存检测
  - 检测 /proc/self/maps 中的 frida 相关库
    - frida-agent
    - frida-gadget
    - libfrida
    - gum-js-loop
  - 检测内存中 "LIBFRIDA" 字符串
- [ ] 命名管道检测
  - 检测 /data/local/tmp 下的 linjector 管道
- [ ] 线程名检测
  - 检测 frida 特有的线程名
  - gmain / gdbus / gum-js-loop / pool-frida
- [ ] Native 函数完整性检测
  - 比较 libc.so 内存和磁盘版本
  - 检测 inline hook 痕迹

##### 1.2.4 Substrate / Cydia 检测
- [ ] 文件检测
  - /Library/MobileSubstrate/MobileSubstrate.dylib
- [ ] 包名检测
  - com.saurik.substrate

##### 1.2.5 通用 Hook 检测
- [ ] GOT/PLT Hook 检测
  - 检测 GOT 表项是否被修改
- [ ] Inline Hook 检测
  - 检测函数入口指令是否被篡改
  - 检测跳转指令 (B/BL/BX)
- [ ] 系统函数完整性检测
  - 比较关键系统函数内存与磁盘差异

---

#### 1.3 虚拟机/模拟器检测 (Emulator Detection)

##### 1.3.1 Build 属性检测
- [ ] Build.FINGERPRINT 检测
  - 包含 "generic" / "vbox" / "test-keys"
- [ ] Build.MODEL 检测
  - "google_sdk" / "Emulator" / "Android SDK built for x86"
  - "Genymotion" / "vmos" / "nox"
- [ ] Build.MANUFACTURER 检测
  - "Genymotion" / "unknown" / "Google"
- [ ] Build.BRAND 检测
  - "generic" / "generic_x86"
- [ ] Build.DEVICE 检测
  - "generic" / "vbox86p" / "nox"
- [ ] Build.PRODUCT 检测
  - "sdk" / "google_sdk" / "sdk_x86"
- [ ] Build.HARDWARE 检测
  - "goldfish" / "ranchu" / "vbox86"
- [ ] ro.build.flavor 检测
  - 检测是否包含 "vbox"
  - 检测是否缺失此属性

##### 1.3.2 硬件特征检测
- [ ] CPU ABI 检测
  - 检测 x86/x86_64 架构在真机上的异常
- [ ] QEMU 虚拟机检测 (ARM 模拟器)
  - PC 寄存器实时更新检测
  - QEMU 指令翻译特征检测
- [ ] VirtualBox 检测 (x86 模拟器)
  - 检测 VBox 驱动特征
- [ ] 传感器检测
  - 传感器数量异常（真机通常 > 10 个）
  - 缺少加速度计、陀螺仪、温度传感器
  - 传感器返回值异常（全为 0）
- [ ] 电池检测
  - 电池状态始终为充电
  - 电池电量固定不变
  - 缺少电池温度信息
- [ ] 蓝牙检测
  - 缺少蓝牙适配器

##### 1.3.3 特定模拟器文件检测
- [ ] 通用模拟器文件
  - /dev/qemu_pipe
  - /dev/qemu_trace
  - /dev/goldfish_pipe
  - /system/lib/libc_malloc_debug_qemu.so
  - /sys/qemu_trace
  - /system/bin/qemu-props
  - init.goldfish.rc
  - init.ranchu.rc
- [ ] 夜神模拟器 (Nox)
  - /data/data/com.bignox.app.store.hd
  - /system/bin/nox
  - nox-prop / nox-vbox-sf
- [ ] 雷电模拟器 (LDPlayer)
  - /system/bin/ldinit
  - /system/bin/ldmountsf
- [ ] 逍遥模拟器 (MEmu)
  - /data/data/com.microvirt.guide
  - /data/data/com.microvirt.market
- [ ] BlueStacks
  - /data/data/com.bluestacks.settings
  - /mnt/windows/BstSharedFolder
- [ ] Genymotion
  - /dev/socket/genyd
  - /system/bin/genybaseband
- [ ] 腾讯手游助手
  - com.tencent.tinput

##### 1.3.4 系统属性检测
- [ ] 检测 /proc/self/cgroup（部分模拟器缺失）
- [ ] 检测 IMEI/IMSI 异常值
  - 全 0 / 全 1 / 000000000000000
- [ ] 检测手机号异常
- [ ] 检测运营商信息异常

##### 1.3.5 多开/分身检测
- [ ] 检测应用数据目录异常
  - /data/data 路径是否正常
- [ ] 检测 UID 异常
- [ ] 检测 Virtual Xposed / VirtualApp
- [ ] 检测平行空间/双开助手等分身应用

---

#### 1.4 调试检测 (Debug Detection)

##### 1.4.1 状态标志检测
- [ ] 检测 android:debuggable 标志
  - ApplicationInfo.FLAG_DEBUGGABLE
- [ ] 检测 Debug.isDebuggerConnected()
- [ ] 检测 Debug.waitingForDebugger()

##### 1.4.2 TracerPid 检测
- [ ] 读取 /proc/self/status
  - 检测 TracerPid 是否为 0
- [ ] 读取 /proc/self/task/[tid]/status
  - 检测所有线程的 TracerPid

##### 1.4.3 Ptrace 检测
- [ ] Ptrace 自我保护
  - ptrace(PTRACE_TRACEME, 0, 0, 0)
  - 防止其他进程附加调试
- [ ] 多进程互相 ptrace 保护
- [ ] Fork 检测
  - 子进程 ptrace 父进程检测

##### 1.4.4 调试端口检测
- [ ] 检测 /proc/net/tcp
  - IDA 默认端口 23946
  - GDB server 默认端口
  - LLDB server 端口
- [ ] 检测 JDWP 端口
  - 检测 Java 调试端口

##### 1.4.5 调试器文件检测
- [ ] 检测 android_server 文件
  - /data/local/tmp/android_server
  - /data/local/tmp/android_server64
- [ ] 检测 gdbserver
- [ ] 检测 lldb-server

##### 1.4.6 时间差检测
- [ ] 两条指令间时间差检测
- [ ] 函数执行时间异常检测
- [ ] 使用多种时间源
  - clock_gettime
  - gettimeofday
  - RDTSC (x86)

##### 1.4.7 断点检测
- [ ] 软件断点检测
  - 检测 BKPT 指令 (ARM: 0xE1200070)
  - 检测 INT3 指令 (x86: 0xCC)
- [ ] 内存断点检测
  - 扫描代码段是否存在断点指令
- [ ] 硬件断点检测
  - 检测调试寄存器

##### 1.4.8 信号处理检测
- [ ] 设置 SIGTRAP 信号处理器
  - 检测信号是否被拦截
- [ ] 设置 SIGSTOP/SIGCONT 处理

##### 1.4.9 其他调试检测
- [ ] 检测 USB 调试开关
  - Settings.Global.ADB_ENABLED
- [ ] 检测开发者选项
  - Settings.Global.DEVELOPMENT_SETTINGS_ENABLED
- [ ] 检测 /proc/self/wchan
  - 检测是否处于 ptrace_stop 状态

---

#### 1.5 内存检测 (Memory Detection)

##### 1.5.1 内存完整性检测
- [ ] 代码段 CRC/Hash 校验
  - 计算 .text 段 CRC32
  - 计算关键函数 Hash
- [ ] SO 库完整性检测
  - 比较内存中 SO 与磁盘文件差异
  - 重点检测 libc.so / libart.so
- [ ] DEX 文件完整性检测
  - classes.dex CRC 校验
  - ODEX/VDEX 完整性校验

##### 1.5.2 内存映射检测
- [ ] 解析 /proc/self/maps
  - 检测可疑内存映射
  - 检测匿名可执行内存区域
  - 检测 rwx 权限区域
- [ ] 检测注入的 SO 库
- [ ] 检测内存中的可疑字符串
  - "frida" / "xposed" / "substrate"

##### 1.5.3 内存监控检测
- [ ] 使用 inotify 监控
  - 监控 /proc/self/mem 读取
  - 监控 /proc/self/pagemap 读取
  - 监控 /proc/self/maps 读取
- [ ] 检测内存 dump 行为

---

#### 1.6 完整性校验 (Integrity Verification)

##### 1.6.1 APK 签名校验
- [ ] 获取 APK 签名证书
- [ ] 校验签名证书哈希
- [ ] 检测 V1/V2/V3 签名
- [ ] 检测签名是否被修改

##### 1.6.2 DEX 文件校验
- [ ] classes.dex CRC32 校验
- [ ] DEX 文件 Hash 校验
- [ ] 多 DEX 文件校验

##### 1.6.3 SO 库校验
- [ ] Native 库文件 Hash 校验
- [ ] 库文件大小校验

##### 1.6.4 资源文件校验
- [ ] AndroidManifest.xml 校验
- [ ] 资源文件完整性校验

##### 1.6.5 代码完整性校验
- [ ] 关键函数 CRC 校验
- [ ] 运行时代码完整性检测
- [ ] 自校验机制

---

#### 1.7 异常文件检测 (Suspicious File Detection)

##### 1.7.1 Root 相关文件
- [ ] /system/bin/su
- [ ] /system/xbin/su
- [ ] /sbin/su
- [ ] /system/app/Superuser.apk
- [ ] /data/data/com.topjohnwu.magisk

##### 1.7.2 Hook 框架文件
- [ ] /system/framework/XposedBridge.jar
- [ ] /data/local/tmp/frida-server
- [ ] /data/adb/lspd
- [ ] /data/adb/modules

##### 1.7.3 调试工具文件
- [ ] /data/local/tmp/android_server
- [ ] /data/local/tmp/gdbserver
- [ ] /data/local/tmp/lldb-server
- [ ] /data/local/tmp/strace

##### 1.7.4 模拟器特征文件
- [ ] /dev/qemu_pipe
- [ ] /dev/socket/genyd
- [ ] /system/bin/nox
- [ ] /fstab.goldfish

##### 1.7.5 恶意软件相关
- [ ] 检测可疑 APK
- [ ] 检测可疑脚本文件

---

#### 1.8 网络环境检测 (Network Detection)

##### 1.8.1 代理检测
- [ ] 检测系统代理设置
  - System.getProperty("http.proxyHost")
  - System.getProperty("http.proxyPort")
- [ ] 检测 WiFi 代理设置
- [ ] 检测 APN 代理

##### 1.8.2 VPN 检测
- [ ] 检测 NetworkCapabilities
  - NET_CAPABILITY_NOT_VPN
- [ ] 检测 /sys/class/net 接口
  - tun0 / ppp0 / tap0
- [ ] 读取 /proc/net/route 检测

##### 1.8.3 抓包工具检测
- [ ] 检测证书安装
  - 用户证书数量异常
- [ ] 检测 Charles / Fiddler 证书
- [ ] SSL Pinning 实现

---

#### 1.9 运行环境检测 (Runtime Detection)

##### 1.9.1 ART/Dalvik 检测
- [ ] 检测运行时类型
- [ ] 检测 ART 版本

##### 1.9.2 SELinux 检测
- [ ] 检测 SELinux 状态
  - Enforcing / Permissive / Disabled
- [ ] 读取 /sys/fs/selinux/enforce

##### 1.9.3 Bootloader 检测
- [ ] 检测 Bootloader 解锁状态
- [ ] 检测 ro.boot.verifiedbootstate

##### 1.9.4 系统完整性检测
- [ ] Google Play Integrity API
- [ ] SafetyNet Attestation (已废弃)
- [ ] 设备证明

---

#### 1.10 进程检测 (Process Detection)

##### 1.10.1 可疑进程检测
- [ ] 遍历 /proc 目录
- [ ] 检测 frida-server 进程
- [ ] 检测 android_server 进程
- [ ] 检测 gdbserver 进程
- [ ] 检测可疑的 daemon 进程

##### 1.10.2 父进程检测
- [ ] 检测 /proc/self/stat
- [ ] 检测父进程是否异常
- [ ] 检测是否从 adb shell 启动

##### 1.10.3 线程检测
- [ ] 遍历 /proc/self/task
- [ ] 检测可疑线程名
- [ ] 检测 Frida 特有线程

### 2. 设备指纹 (Device Fingerprint)

> **核心原则**: 同一信息通过多种方式获取，比对检测是否被篡改

#### 2.1 多层获取架构

##### 2.1.1 Java API 层获取
通过 Android SDK API 获取设备信息（易被 Hook）
- [ ] TelephonyManager API
- [ ] Build 类静态字段
- [ ] Settings.Secure / Settings.System
- [ ] PackageManager
- [ ] SensorManager

##### 2.1.2 Native libc 层获取
通过 JNI 调用 libc 库函数获取（可被 PLT/GOT Hook）
- [ ] fopen/fread 读取 /proc /sys 文件
- [ ] access/stat 检测文件
- [ ] getprop 获取系统属性
- [ ] ioctl 获取硬件信息

##### 2.1.3 直接 Syscall/SVC 获取 (重点)
绕过 libc 直接发起系统调用（最难被 Hook）
```c
// ARM64 直接系统调用示例
__asm__ volatile(
    "mov x8, %1\n"      // syscall number
    "mov x0, %2\n"      // arg0
    "mov x1, %3\n"      // arg1
    "svc #0\n"          // 触发系统调用
    "mov %0, x0\n"      // 返回值
    : "=r"(ret)
    : "r"(syscall_num), "r"(arg0), "r"(arg1)
    : "x0", "x1", "x8"
);
```
- [ ] SYS_openat - 打开文件
- [ ] SYS_read - 读取文件
- [ ] SYS_faccessat - 检测文件存在
- [ ] SYS_stat/fstat - 获取文件状态
- [ ] SYS_getdents64 - 遍历目录
- [ ] SYS_uname - 获取系统信息

##### 2.1.4 内核文件直读
直接读取系统文件获取原始信息
- [ ] /proc/cpuinfo - CPU 信息
- [ ] /proc/meminfo - 内存信息
- [ ] /proc/version - 内核版本
- [ ] /proc/self/maps - 内存映射
- [ ] /sys/class/net/*/address - MAC 地址
- [ ] /sys/class/android_usb/android0/iSerial - 序列号
- [ ] /sys/devices/soc0/* - SoC 信息
- [ ] /system/build.prop - 系统属性
- [ ] /vendor/build.prop - 厂商属性

---

#### 2.2 设备标识符采集

##### 2.2.1 ANDROID_ID
| 获取方式 | 方法 |
|---------|------|
| Java API | Settings.Secure.getString(contentResolver, "android_id") |
| Native | 读取 /data/system/users/0/settings_ssaid.xml |
| Syscall | SYS_openat + SYS_read 直读文件 |

##### 2.2.2 设备序列号 (Serial)
| 获取方式 | 方法 |
|---------|------|
| Java API | Build.SERIAL / Build.getSerial() |
| Native getprop | __system_property_get("ro.serialno") |
| Native 文件 | 读取 /sys/class/android_usb/android0/iSerial |
| Syscall | 直接系统调用读取 |

##### 2.2.3 IMEI / MEID
| 获取方式 | 方法 |
|---------|------|
| Java API | TelephonyManager.getDeviceId() / getImei() |
| Native | 通过 Binder 调用 Phone Service |
| AT 命令 | 直接发送 AT+CGSN 到 modem (需权限) |

##### 2.2.4 MAC 地址
| 获取方式 | 方法 |
|---------|------|
| Java API | WifiManager.getConnectionInfo() (已废弃) |
| NetworkInterface | NetworkInterface.getHardwareAddress() |
| Native 文件 | /sys/class/net/wlan0/address |
| Native ioctl | SIOCGIFHWADDR |
| Syscall | 直接读取 sysfs |

##### 2.2.5 Build 信息
| 获取方式 | 方法 |
|---------|------|
| Java API | Build.FINGERPRINT, Build.MODEL 等 |
| Native getprop | __system_property_get() |
| Native 文件 | 直读 /system/build.prop |
| Syscall | SYS_openat 读取 build.prop |

##### 2.2.6 CPU 信息
| 获取方式 | 方法 |
|---------|------|
| Java API | Runtime.getRuntime().availableProcessors() |
| Native sysconf | sysconf(_SC_NPROCESSORS_CONF) |
| Native 文件 | /proc/cpuinfo |
| Native auxval | getauxval(AT_HWCAP) |
| Syscall | 直读 /proc/cpuinfo |

##### 2.2.7 内存信息
| 获取方式 | 方法 |
|---------|------|
| Java API | ActivityManager.getMemoryInfo() |
| Native sysconf | sysconf(_SC_PHYS_PAGES) * sysconf(_SC_PAGE_SIZE) |
| Native 文件 | /proc/meminfo |
| Syscall | 直读 /proc/meminfo |

##### 2.2.8 存储信息
| 获取方式 | 方法 |
|---------|------|
| Java API | StatFs |
| Native statfs | statfs() 系统调用 |
| Native 文件 | /proc/mounts, /proc/partitions |
| Syscall | SYS_statfs64 |

---

#### 2.3 硬件指纹采集

##### 2.3.1 屏幕指纹
- [ ] Java: DisplayMetrics (density, widthPixels, heightPixels)
- [ ] Native: ANativeWindow / Surface
- [ ] 文件: /sys/class/graphics/fb0/virtual_size

##### 2.3.2 传感器指纹
- [ ] Java: SensorManager.getSensorList()
- [ ] Native: ASensorManager_getSensorList()
- [ ] 传感器类型、厂商、分辨率、最大范围

##### 2.3.3 摄像头指纹
- [ ] Java: CameraManager.getCameraIdList()
- [ ] Native: ACameraManager
- [ ] 摄像头数量、分辨率、特性

##### 2.3.4 音频指纹
- [ ] Java: AudioManager
- [ ] Native: AAudio
- [ ] 音频输入/输出设备、采样率

##### 2.3.5 GPU 指纹
- [ ] EGL: eglQueryString (EGL_VENDOR, EGL_RENDERER)
- [ ] OpenGL ES: glGetString (GL_VENDOR, GL_RENDERER)

##### 2.3.6 蓝牙指纹
- [ ] Java: BluetoothAdapter.getAddress()
- [ ] 文件: /sys/class/bluetooth/hci0/address

---

#### 2.4 软件指纹采集

##### 2.4.1 系统属性指纹
- [ ] ro.build.fingerprint
- [ ] ro.build.display.id
- [ ] ro.product.model / brand / device / board
- [ ] ro.hardware
- [ ] ro.bootimage.build.fingerprint
- [ ] ro.vendor.build.fingerprint

##### 2.4.2 内核指纹
- [ ] /proc/version
- [ ] /proc/sys/kernel/osrelease
- [ ] /proc/sys/kernel/version

##### 2.4.3 Boot ID
- [ ] /proc/sys/kernel/random/boot_id
- [ ] 每次启动变化，可用于检测重启

##### 2.4.4 Bootloader 信息
- [ ] ro.boot.hardware
- [ ] ro.boot.serialno
- [ ] ro.bootloader

##### 2.4.5 应用指纹
- [ ] 已安装应用列表 Hash
- [ ] 系统应用签名
- [ ] 包名 + 版本号组合

---

#### 2.5 网络指纹采集

##### 2.5.1 WiFi 信息
| 获取方式 | 方法 |
|---------|------|
| Java API | WifiInfo.getBSSID(), getSSID() |
| Native | ioctl SIOCGIFHWADDR |
| 文件 | /sys/class/net/wlan0/* |

##### 2.5.2 运营商信息
- [ ] TelephonyManager.getNetworkOperator()
- [ ] TelephonyManager.getSimOperator()
- [ ] IMSI (需要权限)

##### 2.5.3 IP 地址
- [ ] Java: NetworkInterface.getInetAddresses()
- [ ] Native: getifaddrs()
- [ ] 文件: /proc/net/route

---

#### 2.6 指纹比对与篡改检测 (核心)

##### 2.6.1 多源比对策略
```
┌─────────────────────────────────────────────────────────┐
│                    指纹采集与比对流程                      │
├─────────────────────────────────────────────────────────┤
│  ┌───────────┐   ┌───────────┐   ┌───────────┐         │
│  │ Java API  │   │Native libc│   │  Syscall  │         │
│  │   获取    │   │   获取    │   │   获取    │         │
│  └─────┬─────┘   └─────┬─────┘   └─────┬─────┘         │
│        │               │               │               │
│        ▼               ▼               ▼               │
│  ┌─────────────────────────────────────────────┐       │
│  │              比对引擎 (Compare Engine)        │       │
│  │  - 三路结果一致 → 正常                        │       │
│  │  - Java ≠ Native = Syscall → Java层被Hook    │       │
│  │  - Java = Native ≠ Syscall → libc被Hook      │       │
│  │  - 全不一致 → 深度篡改                        │       │
│  └─────────────────────────────────────────────┘       │
└─────────────────────────────────────────────────────────┘
```

##### 2.6.2 篡改检测规则
- [ ] ANDROID_ID 三路比对
- [ ] Build 信息三路比对
- [ ] MAC 地址三路比对
- [ ] 序列号三路比对
- [ ] CPU 信息三路比对
- [ ] 内存信息三路比对

##### 2.6.3 异常判定条件
| 异常类型 | 判定条件 |
|---------|----------|
| Xposed/LSPosed Hook | Java API 返回值异常，Native 正常 |
| Frida Hook | Native libc 返回值异常，Syscall 正常 |
| 内核级篡改 | Syscall 也返回异常值 |
| 改机工具 | 多项信息同时异常 |
| 模拟器 | 硬件信息与 Build 信息不匹配 |

##### 2.6.4 可信度评分
- [ ] 根据比对结果计算可信度分数 (0-100)
- [ ] 分数越低风险越高
- [ ] 设置阈值触发警告

---

#### 2.7 综合指纹生成

##### 2.7.1 指纹融合算法
- [ ] 选择稳定的硬件标识符
- [ ] 多维度信息加权组合
- [ ] 抗篡改 Hash 计算
- [ ] 版本兼容性处理

##### 2.7.2 指纹唯一性保证
- [ ] 硬件 ID (不可变) + 软件 ID (可变) 组合
- [ ] 使用 HMAC 防止伪造
- [ ] 服务端二次校验

##### 2.7.3 指纹稳定性处理
- [ ] 过滤高变化率属性
- [ ] 记录变化历史
- [ ] 相似度匹配算法

##### 2.7.4 最终指纹输出
```
DeviceFingerprint = HMAC-SHA256(
    ANDROID_ID +
    Build.FINGERPRINT +
    CPU_INFO_HASH +
    MAC_ADDRESS +
    SCREEN_INFO +
    SENSOR_LIST_HASH +
    ...
)
```

### 3. 设备信息与机型合法性检测 (Device Information & Model Validation)

> **核心目标**: 采集设备信息并验证机型合法性，识别改机/伪装行为

#### 3.0 机型合法性检测架构

##### 3.0.1 改机检测原理
```
┌─────────────────────────────────────────────────────────────────┐
│                      机型合法性检测流程                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐        │
│   │ Build 信息  │    │ ROM 特征    │    │ 厂商服务    │        │
│   │ 采集        │    │ 检测        │    │ 检测        │        │
│   └──────┬──────┘    └──────┬──────┘    └──────┬──────┘        │
│          │                  │                  │               │
│          ▼                  ▼                  ▼               │
│   ┌─────────────────────────────────────────────────────┐      │
│   │                 一致性校验引擎                        │      │
│   │                                                     │      │
│   │  检测项:                                            │      │
│   │  • Build.BRAND ↔ ROM特征 ↔ 厂商服务 是否匹配        │      │
│   │  • Build.FINGERPRINT 格式是否符合厂商规范            │      │
│   │  • 硬件信息与机型数据库是否匹配                      │      │
│   │  • CPU/GPU 与声称机型是否一致                       │      │
│   └─────────────────────────────────────────────────────┘      │
│                            │                                   │
│                            ▼                                   │
│   ┌─────────────────────────────────────────────────────┐      │
│   │  判定结果: 正常机型 / 疑似改机 / 确认改机             │      │
│   └─────────────────────────────────────────────────────┘      │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

##### 3.0.2 典型改机场景
| 场景 | 异常表现 | 检测方法 |
|-----|---------|---------|
| 小米机型有华为服务 | BRAND=Xiaomi 但存在 HMS | 厂商服务包检测 |
| 伪装高端机型 | Build.MODEL=旗舰机 但 CPU 是低端 | 硬件一致性校验 |
| 模拟器伪装真机 | Build 信息正常但硬件特征异常 | 硬件指纹检测 |
| ROM 刷机修改 | FINGERPRINT 格式异常 | 格式规范校验 |
| 改机软件修改 | 多层获取结果不一致 | 三层比对检测 |

---

#### 3.1 Build 信息采集

##### 3.1.1 核心 Build 属性
| 属性 | 说明 | 示例值 |
|-----|------|--------|
| Build.BRAND | 品牌 | Xiaomi, HUAWEI, OPPO |
| Build.MANUFACTURER | 制造商 | Xiaomi, Huawei, OPPO |
| Build.MODEL | 型号 | Mi 14, Mate 60 Pro |
| Build.DEVICE | 设备代号 | sheng, ALN-AL00 |
| Build.PRODUCT | 产品名 | sheng, ALN-AL00 |
| Build.BOARD | 主板 | taro, kirin9000s |
| Build.HARDWARE | 硬件 | qcom, kirin |
| Build.FINGERPRINT | 完整指纹 | 见下方格式 |

##### 3.1.2 Build.FINGERPRINT 格式规范
```
标准格式:
[BRAND]/[PRODUCT]/[DEVICE]:[VERSION.RELEASE]/[BUILD_ID]/[VERSION.INCREMENTAL]:[TYPE]/[TAGS]

示例:
Xiaomi/sheng/sheng:14/UKQ1.230804.001/V816.0.4.0.UNCCNXM:user/release-keys
HUAWEI/ALN-AL00/HWALN:14/HUAWEIALN-AL00/104.0.0.68C00:user/release-keys
```

##### 3.1.3 Build 信息多层获取
| 获取方式 | 方法 |
|---------|------|
| Java API | android.os.Build.* |
| 反射 SystemProperties | SystemProperties.get("ro.build.*") |
| Native getprop | __system_property_get() |
| 直读文件 | /system/build.prop, /vendor/build.prop |
| Syscall | SYS_openat 读取 build.prop |

---

#### 3.2 厂商 ROM 特征检测

##### 3.2.1 厂商 ROM 标识属性
| 厂商 | ROM 名称 | 检测属性 | 示例值 |
|-----|---------|---------|--------|
| 小米 | MIUI | ro.miui.ui.version.name | V14, V15 |
| 小米 | HyperOS | ro.mi.os.version.name | OS1.0 |
| 华为 | EMUI | ro.build.version.emui | EmotionUI_14.0.0 |
| 华为 | HarmonyOS | hw_sc.build.platform.version | 4.0.0 |
| 荣耀 | MagicOS | ro.build.version.magic | 7.0 |
| OPPO | ColorOS | ro.build.version.opporom | V14.0 |
| vivo | OriginOS | ro.vivo.os.version | 14 |
| vivo | FuntouchOS | ro.vivo.os.name | funtouch |
| 一加 | OxygenOS | ro.build.ota.versionname | - |
| 一加 | ColorOS | ro.oplus.version | - |
| 三星 | One UI | ro.build.version.oneui | 60100 |
| 真我 | realme UI | ro.build.version.realmeui | 5.0 |

##### 3.2.2 ROM 特征检测代码
```java
// 检测 MIUI
public static boolean isMIUI() {
    return !TextUtils.isEmpty(getSystemProperty("ro.miui.ui.version.name"));
}

// 检测 EMUI/HarmonyOS
public static boolean isEMUI() {
    return !TextUtils.isEmpty(getSystemProperty("ro.build.version.emui"));
}

// 检测 ColorOS
public static boolean isColorOS() {
    return !TextUtils.isEmpty(getSystemProperty("ro.build.version.opporom"));
}
```

##### 3.2.3 ROM 与品牌一致性规则
| Build.BRAND | 应存在的 ROM 属性 | 不应存在的属性 |
|-------------|------------------|---------------|
| Xiaomi/Redmi | ro.miui.* 或 ro.mi.os.* | ro.build.version.emui |
| HUAWEI | ro.build.version.emui 或 hw_sc.* | ro.miui.* |
| HONOR | ro.build.version.magic | ro.miui.*, ro.build.version.emui |
| OPPO | ro.build.version.opporom | ro.miui.*, ro.build.version.emui |
| vivo | ro.vivo.os.* | ro.miui.*, ro.build.version.opporom |
| OnePlus | ro.build.ota.versionname | ro.miui.* |
| samsung | ro.build.version.oneui | ro.miui.*, ro.build.version.emui |
| realme | ro.build.version.realmeui | ro.miui.* |

---

#### 3.3 厂商服务包检测 (重点)

##### 3.3.1 厂商服务包列表
| 厂商 | 服务类型 | 包名 | 说明 |
|-----|---------|------|------|
| **Google** | GMS | com.google.android.gms | Google Play Services |
| | | com.google.android.gsf | Google Services Framework |
| | | com.android.vending | Google Play Store |
| **华为** | HMS | com.huawei.hwid | 华为账号 |
| | | com.huawei.hms.core | HMS Core |
| | | com.huawei.appmarket | 华为应用市场 |
| | 推送 | com.huawei.hms.push | 华为推送 |
| **小米** | 服务 | com.xiaomi.account | 小米账号 |
| | | com.xiaomi.market | 小米应用商店 |
| | 推送 | com.xiaomi.mipush.sdk | 小米推送 |
| | | com.xiaomi.xmsf | 小米推送服务 |
| **OPPO** | 服务 | com.heytap.openid | HeyTap 账号 |
| | | com.oppo.market | OPPO 软件商店 |
| | 推送 | com.heytap.msp | OPPO 推送 |
| | | com.coloros.oppopush | ColorOS 推送 |
| **vivo** | 服务 | com.vivo.id | vivo 账号 |
| | | com.bbk.appstore | vivo 应用商店 |
| | 推送 | com.vivo.push | vivo 推送 |
| **荣耀** | 服务 | com.hihonor.id | 荣耀账号 |
| | 推送 | com.hihonor.push | 荣耀推送 |
| **魅族** | 推送 | com.meizu.cloud.pushsdk | 魅族推送 |

##### 3.3.2 服务包与品牌一致性规则
```
┌────────────────────────────────────────────────────────────────┐
│                   厂商服务一致性检测规则                         │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│   正常情况:                                                    │
│   • 小米手机 → 存在小米服务 + 可能有 GMS                        │
│   • 华为手机 → 存在 HMS (新机无 GMS) 或 GMS+HMS (老机)          │
│   • OPPO 手机 → 存在 OPPO/HeyTap 服务 + GMS                    │
│                                                                │
│   异常情况 (疑似改机):                                          │
│   • Build.BRAND=Xiaomi 但存在 HMS 核心服务 → 改机              │
│   • Build.BRAND=HUAWEI 但存在小米推送服务 → 改机               │
│   • Build.BRAND=OPPO 但存在华为账号服务 → 改机                  │
│   • 任意品牌存在多家厂商核心服务 → 高度可疑                     │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

##### 3.3.3 服务检测实现
```java
// 检测厂商服务包是否安装
public static boolean isPackageInstalled(Context ctx, String pkg) {
    try {
        ctx.getPackageManager().getPackageInfo(pkg, 0);
        return true;
    } catch (NameNotFoundException e) {
        return false;
    }
}

// 多层检测: Native 层检测 /data/data/包名 目录
// Syscall 层: faccessat 检测目录存在
```

---

#### 3.4 硬件信息与机型一致性检测

##### 3.4.1 CPU 与机型匹配
| 机型系列 | 预期 CPU | 检测方法 |
|---------|---------|---------|
| 小米14系列 | Snapdragon 8 Gen 3 | /proc/cpuinfo Hardware |
| 华为Mate60系列 | Kirin 9000S | ro.hardware |
| OPPO Find X7 | Dimensity 9300 | CPU 特征 |

##### 3.4.2 硬件参数合理性检测
| 检测项 | 异常判定 |
|-------|---------|
| 屏幕分辨率 | 与机型数据库不匹配 |
| 内存大小 | 声称高端机但内存 < 6GB |
| 存储空间 | 与机型规格严重不符 |
| 摄像头数量 | 与官方参数不符 |
| 传感器列表 | 缺少该机型应有的传感器 |

##### 3.4.3 机型数据库校验
- [ ] 建立主流机型硬件参数数据库
- [ ] 比对 Build.MODEL 与实际硬件参数
- [ ] 检测参数是否在合理范围内

---

#### 3.5 Build.FINGERPRINT 格式校验

##### 3.5.1 各厂商 FINGERPRINT 格式特征
| 厂商 | 格式特征 |
|-----|---------|
| 小米 | Xiaomi/[product]/[device]:版本/.../release-keys |
| 华为 | HUAWEI/[model]/HW[code]:版本/.../release-keys |
| OPPO | OPPO/[model]/[model]:版本/.../release-keys |
| vivo | vivo/[model]/[model]:版本/.../release-keys |
| 三星 | samsung/[model]/[model]:版本/.../release-keys |

##### 3.5.2 异常 FINGERPRINT 特征
- [ ] 包含 "generic" (模拟器特征)
- [ ] 包含 "test-keys" (测试版本)
- [ ] 包含 "userdebug" (调试版本)
- [ ] 格式不符合任何已知厂商规范
- [ ] BRAND 与 FINGERPRINT 中的品牌不一致

---

#### 3.6 系统版本信息采集

##### 3.6.1 Android 版本信息
| 属性 | 说明 |
|-----|------|
| Build.VERSION.RELEASE | Android 版本号 (如 14) |
| Build.VERSION.SDK_INT | API Level (如 34) |
| Build.VERSION.CODENAME | 版本代号 |
| Build.VERSION.SECURITY_PATCH | 安全补丁日期 |
| Build.VERSION.BASE_OS | 基础系统版本 |

##### 3.6.2 内核版本
- [ ] /proc/version
- [ ] /proc/sys/kernel/osrelease
- [ ] 内核版本与 Android 版本匹配性检测

---

#### 3.7 基础设备信息展示

##### 3.7.1 品牌与型号
- [ ] Build.BRAND - 品牌
- [ ] Build.MODEL - 型号
- [ ] Build.MANUFACTURER - 制造商
- [ ] Build.DEVICE - 设备代号
- [ ] Build.PRODUCT - 产品名

##### 3.7.2 系统信息
- [ ] Android 版本
- [ ] API Level
- [ ] ROM 版本 (MIUI/EMUI/ColorOS 等)
- [ ] 安全补丁级别
- [ ] 内核版本

##### 3.7.3 硬件信息
- [ ] CPU 型号和核心数
- [ ] 内存大小 (RAM)
- [ ] 存储空间 (ROM)
- [ ] 屏幕分辨率和密度
- [ ] 摄像头信息

##### 3.7.4 网络信息
- [ ] 当前网络类型 (WiFi/4G/5G)
- [ ] WiFi 信息 (SSID, BSSID)
- [ ] IP 地址
- [ ] 运营商名称

---

#### 3.8 机型合法性评分

##### 3.8.1 评分维度
| 维度 | 权重 | 检测内容 |
|-----|-----|---------|
| Build 一致性 | 25% | 多层获取结果比对 |
| ROM 特征匹配 | 20% | ROM 属性与品牌匹配 |
| 厂商服务匹配 | 25% | 服务包与品牌匹配 |
| 硬件一致性 | 20% | 硬件参数与机型匹配 |
| FINGERPRINT 格式 | 10% | 格式规范性 |

##### 3.8.2 风险等级判定
| 分数 | 等级 | 说明 |
|-----|-----|------|
| 90-100 | 正常 | 机型信息完全合法 |
| 70-89 | 低风险 | 存在轻微不一致，可能是刷机 |
| 50-69 | 中风险 | 多项不一致，疑似改机 |
| 0-49 | 高风险 | 严重不一致，确认改机 |

##### 3.8.3 异常详情输出
```json
{
  "score": 45,
  "risk_level": "HIGH",
  "anomalies": [
    {
      "type": "SERVICE_MISMATCH",
      "detail": "Brand is Xiaomi but HMS Core detected",
      "severity": "HIGH"
    },
    {
      "type": "ROM_MISMATCH",
      "detail": "Brand is Xiaomi but EMUI property found",
      "severity": "HIGH"
    },
    {
      "type": "FINGERPRINT_ABNORMAL",
      "detail": "FINGERPRINT contains 'test-keys'",
      "severity": "MEDIUM"
    }
  ]
}
```

## 技术实现说明

### Native 层实现（推荐）
大部分检测逻辑应在 Native C++ 层实现，原因：
1. 更难被 Hook 绑架
2. 可直接访问底层 API
3. 可读取 /proc 等系统文件
4. 反调试效果更好

### Java 层实现
部分需要 Android SDK API 的功能在 Java 层实现：
1. PackageManager 相关查询
2. Build 类信息获取
3. TelephonyManager 调用
4. 传感器信息获取

## 开发计划
1. 优先实现 Native 层基础框架
2. 实现各检测模块
3. 实现设备指纹生成
4. 实现设备信息采集
5. 统一接口封装
6. 测试和优化

## 注意事项
- 所有检测需要考虑误报率
- 针对不同 Android 版本做兼容处理
- Native 代码需要支持多架构 (armeabi-v7a, arm64-v8a, x86, x86_64)
- 敏感信息采集需要申请相应权限

---

## 当前实现状态 (2025-01)

### 已完成模块

#### ✅ 核心架构
- MainActivity + 底部导航 (3个Fragment)
- 多层检测架构 (Java/Native/Syscall)
- Native JNI 接口 (native-lib.cpp)

#### ✅ 环境检测板块 (EnvironmentFragment)
- Root 检测 (Magisk/KernelSU/APatch/SU文件)
- Hook 检测 (Xposed/Frida/LSPosed)
- 模拟器检测 (特征/硬件/性能)
- 调试检测 (USB调试/调试器/ptrace)
- 网络检测 (VPN/代理)
- 完整性检测

#### ✅ 指纹采集板块 (FingerprintFragment)
- 三层采集架构 (Java/Native/Syscall)
- 多层数据一致性比对
- N/A值智能处理 (不参与比较)
- 多数据源fallback机制

#### ✅ 机型信息板块 (DeviceInfoFragment)
- 基础设备信息采集
- 厂商合法性检测系统
- ROM特征验证
- 厂商服务包检测

#### ✅ UI/启动页
- SplashActivity 启动页 (动画效果)
- 专业安全主题图标
- Material Design 风格

---

## 项目文件结构 (完整)

```
app/src/main/
├── java/com/xff/launch/
│   ├── MainActivity.java                    # 主Activity (底部导航容器)
│   ├── SplashActivity.java                  # ★ 启动页Activity (动画+跳转)
│   │
│   ├── ui/
│   │   ├── environment/
│   │   │   └── EnvironmentFragment.java     # 环境检测页面
│   │   ├── fingerprint/
│   │   │   └── FingerprintFragment.java     # ★ 指纹采集页面 (多层fallback)
│   │   └── deviceinfo/
│   │       └── DeviceInfoFragment.java      # ★ 机型信息页面 (集成合法性检测)
│   │
│   ├── model/
│   │   ├── DetectionItem.java               # 检测项数据模型
│   │   ├── DetectionCategory.java           # 检测分类模型
│   │   ├── FingerprintItem.java             # ★ 指纹项模型 (N/A智能处理)
│   │   └── VendorProfile.java               # ★ 厂商特征配置模型
│   │
│   ├── adapter/
│   │   ├── DetectionAdapter.java            # 检测结果适配器
│   │   ├── FingerprintAdapter.java          # 指纹信息适配器
│   │   └── RomFeatureAdapter.java           # ROM特征适配器
│   │
│   ├── detector/
│   │   ├── RootDetector.java                # Root检测器
│   │   ├── HookDetector.java                # Hook检测器
│   │   ├── EmulatorDetector.java            # 模拟器检测器
│   │   ├── DebugDetector.java               # 调试检测器
│   │   ├── VendorDatabase.java              # ★ 厂商特征数据库 (15+品牌)
│   │   └── DeviceLegitimacyDetector.java    # ★ 机型合法性检测器 (5维度评分)
│   │
│   └── utils/
│       └── [工具类]
│
├── cpp/
│   ├── CMakeLists.txt                       # CMake 配置
│   ├── native-lib.cpp                       # JNI 入口
│   ├── syscall_wrapper.h                    # ★ Syscall封装 (ARM32/ARM64)
│   ├── root_detector.cpp                    # Native Root检测
│   ├── hook_detector.cpp                    # Native Hook检测
│   ├── emulator_detector.cpp                # Native 模拟器检测
│   ├── debug_detector.cpp                   # Native 调试检测
│   └── fingerprint_collector.cpp            # Native 指纹采集
│
└── res/
    ├── layout/
    │   ├── activity_main.xml                # 主布局
    │   ├── activity_splash.xml              # ★ 启动页布局
    │   ├── fragment_environment.xml         # 环境检测布局
    │   ├── fragment_fingerprint.xml         # 指纹信息布局
    │   ├── fragment_device_info.xml         # 机型信息布局
    │   ├── item_detection.xml               # 检测项布局
    │   ├── item_fingerprint.xml             # 指纹项布局
    │   └── item_rom_feature.xml             # ★ ROM特征项布局
    │
    ├── drawable/
    │   ├── ic_launcher_foreground.xml       # ★ 应用图标前景 (盾牌+对勾)
    │   ├── ic_launcher_background.xml       # ★ 应用图标背景 (蓝色渐变)
    │   ├── splash_image.xml                 # ★ 启动页图标 (专业盾牌)
    │   ├── ic_shield.xml                    # ★ 导航图标 (盾牌+扫描线)
    │   ├── ic_fingerprint.xml               # 指纹图标
    │   ├── ic_phone.xml                     # 手机图标
    │   └── [其他图标资源]
    │
    ├── values/
    │   ├── colors.xml                       # 颜色定义
    │   ├── strings.xml                      # 字符串资源
    │   └── themes.xml                       # ★ 主题 (含Splash主题)
    │
    ├── menu/
    │   └── bottom_navigation.xml            # 底部导航菜单
    │
    └── mipmap-*/
        └── [应用图标各分辨率]
```

---

## 关键类详解

### VendorProfile.java - 厂商特征模型
```java
// 用于定义每个品牌的特征配置
public class VendorProfile {
    private String brandName;                    // 品牌名称
    private List<String> brandIdentifiers;       // 品牌标识 (Build.BRAND匹配)
    private List<String> romVersionProperties;   // ROM版本属性 (ro.miui.*, ro.build.version.emui等)
    private List<String> requiredPackages;       // 必装应用包名
    private List<String> optionalPackages;       // 可选应用包名

    // Builder模式构建
    public static class Builder { ... }
}
```

### VendorDatabase.java - 厂商数据库
```java
// 内置 15+ 品牌的特征数据
支持品牌:
├── Xiaomi (小米/红米) - MIUI特征
├── Huawei (华为)      - EMUI特征
├── Honor (荣耀)       - MagicUI特征
├── OPPO              - ColorOS特征
├── OnePlus (一加)     - OxygenOS/ColorOS特征
├── realme            - realmeUI特征
├── vivo              - OriginOS/FuntouchOS特征
├── Samsung (三星)     - One UI特征
├── Meizu (魅族)       - Flyme特征
├── Lenovo (联想)      - ZUI特征
├── ZTE (中兴)         - MyOS特征
├── Sony (索尼)        - 原生Android
├── Google (谷歌)      - Pixel特征
├── ASUS (华硕)        - ZenUI特征
├── LG                - LG UX特征
└── HTC               - Sense UI特征

// 使用方式
VendorProfile profile = VendorDatabase.getProfile(Build.BRAND);
```

### DeviceLegitimacyDetector.java - 合法性检测器
```java
// 5维度评分系统
public class LegitimacyResult {
    int totalScore;              // 总分 (0-100)
    String riskLevel;            // 风险等级 (NORMAL/LOW/MEDIUM/HIGH)
    boolean buildConsistent;     // Build一致性 (Java vs Native)
    boolean romMatched;          // ROM特征匹配
    boolean servicesMatched;     // 厂商服务匹配
    boolean hardwareConsistent;  // 硬件一致性
    boolean fingerprintValid;    // 指纹格式有效
    List<String> anomalies;      // 异常详情列表
}

// 检测方法
checkBuildConsistency()      // 多层Build信息比对
checkRomMatch()              // ROM版本属性验证
checkVendorServices()        // 厂商预装应用检测
checkHardwareConsistency()   // 硬件参数合理性
checkFingerprintFormat()     // Build.FINGERPRINT格式验证
```

### FingerprintItem.java - 指纹项模型 (N/A处理)
```java
// 智能一致性检查 - 跳过N/A值
private void checkConsistency() {
    String firstValue = null;
    int validValueCount = 0;
    for (String value : layerValues.values()) {
        // 跳过无效值
        if (value == null || value.isEmpty() || value.equals("N/A")) continue;
        validValueCount++;
        if (firstValue == null) {
            firstValue = value;
        } else if (!firstValue.equals(value)) {
            consistent = false;  // 不一致
            return;
        }
    }
    // 有效值少于2个时视为一致
    consistent = validValueCount < 2 || firstValue != null;
}

// 获取主值 - 优先返回有效值
public String getPrimaryValue() {
    for (String value : layerValues.values()) {
        if (isValidValue(value)) return value;
    }
    return "N/A";
}
```

---

## Native层关键实现

### syscall_wrapper.h - 直接系统调用
```c
// ARM64 架构 - 直接SVC调用
#if defined(__aarch64__)
static inline long syscall_wrapper(long number, ...) {
    register long x8 __asm__("x8") = number;
    register long x0 __asm__("x0");
    // ... 参数处理
    __asm__ volatile("svc #0" : "=r"(x0) : "r"(x8), ... : "memory");
    return x0;
}
#endif

// ARM32 架构 - 使用标准syscall() (避免r7寄存器冲突)
#if defined(__arm__)
#define syscall_wrapper syscall
#endif

// 文件存在检测
static inline int syscall_faccessat(const char *path) {
    return syscall_wrapper(__NR_faccessat, AT_FDCWD, path, F_OK, 0);
}

// 系统属性读取
static inline int syscall_read_prop(const char *file, char *buf, size_t size) {
    int fd = syscall_wrapper(__NR_openat, AT_FDCWD, file, O_RDONLY);
    if (fd < 0) return -1;
    ssize_t n = syscall_wrapper(__NR_read, fd, buf, size - 1);
    syscall_wrapper(__NR_close, fd);
    return (n > 0) ? 0 : -1;
}
```

---

## 配色方案

| 用途 | 颜色名 | 色值 | 说明 |
|-----|-------|------|------|
| 主色 | primary | #2196F3 | 科技蓝 |
| 主色深 | primary_dark | #1976D2 | 状态栏/标题 |
| 强调色 | accent | #4CAF50 | 绿色-安全标识 |
| 安全 | status_safe | #4CAF50 | 检测通过 |
| 风险 | status_risk | #F44336 | 检测到风险 |
| 警告 | status_warning | #FF9800 | 潜在风险 |
| 未知 | status_unknown | #9E9E9E | 无法确定 |
| 背景 | background | #F5F5F5 | 页面背景 |
| 卡片 | card_background | #FFFFFF | 卡片背景 |
| 图标背景渐变 | - | #1A237E → #3949AB | 深蓝渐变 |

---

## 已修复问题

### 1. 指纹项空值问题
**问题**: 设备序列号、设备型号、品牌、build指纹等基础指纹项显示为空
**解决**: 在 FingerprintFragment.java 添加多层fallback:
- 优先使用 Build.SERIAL/MODEL/BRAND/FINGERPRINT 直接访问
- 其次使用反射获取
- 再次使用系统属性 (ro.product.*, ro.serialno等)
- 最后返回 "N/A"

### 2. N/A值比对问题
**问题**: N/A值与其他值比较导致误报不一致
**解决**: FingerprintItem.checkConsistency() 中跳过 N/A 值

### 3. ARM32 syscall r7寄存器冲突
**问题**: ARM32 thumb模式下 r7 是帧指针，不能直接用于syscall
**解决**: ARM32使用标准 syscall() 函数代替内联汇编

---

## 启动流程

```
┌─────────────────┐
│ SplashActivity  │
│ (Theme.Launch.  │
│  Splash)        │
│ - 全屏显示      │
│ - 渐入动画      │
│ - 2秒延迟       │
└────────┬────────┘
         │ startActivity
         ▼
┌─────────────────┐
│  MainActivity   │
│ - 底部导航      │
│ - 3个Fragment   │
│ - 状态概览卡片  │
└─────────────────┘
```

---

## 构建命令

```bash
# Debug构建
./gradlew :app:assembleDebug

# Release构建
./gradlew :app:assembleRelease

# 清理
./gradlew clean

# 安装到设备
./gradlew :app:installDebug
```

---

## 下一步开发建议

### 待完善功能
1. **环境检测**: 添加更多2024-2025年新型Root方案检测
2. **指纹采集**: 增加更多硬件指纹项
3. **机型检测**: 扩展厂商数据库，添加更多品牌/机型
4. **UI优化**: 添加检测动画效果
5. **导出功能**: 支持检测报告导出

### 技术优化
1. 优化Native层syscall性能
2. 添加更多反调试检测
3. 完善异常处理和日志记录
