# 更新日志 (Changelog)

本文档记录 Launch 项目的所有重要变更。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.0.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

---

## [1.1.2] - 2025-01-13

### 新增 (Added)
- ✨ 支持 x86 和 x86_64 架构编译
- ✨ 添加对 4 种架构的完整支持（ARM32/ARM64/x86/x86_64）
- 📝 添加完整的 README.md 文档
- 📝 添加 CHANGELOG.md 更新日志

### 修复 (Fixed)
- 🐛 修复 x86/x86_64 架构下的系统调用号兼容性问题
- 🐛 修复 `__NR_fstatat` 在不同架构下的定义缺失
- 🐛 优化 syscall_wrapper.h 中的架构兼容性处理

### 变更 (Changed)
- 🔧 重构 syscall_wrapper.h，统一系统调用接口
- 🔧 优化 x86 架构的系统调用实现（使用标准 syscall 函数）
- 📦 APK 现在包含所有 4 种架构的 native 库

---

## [1.1.1] - 2025-01-12

### 新增 (Added)
- ✨ 添加机型合法性检测功能（5 维度评分系统）
- ✨ 新增 15+ 品牌厂商特征数据库
- ✨ 添加厂商服务包检测（GMS/HMS/小米服务等）
- ✨ 添加 ROM 特征验证功能
- ✨ 实现设备指纹 N/A 值智能处理

### 改进 (Improved)
- 🎨 优化机型信息页面 UI 布局
- 🎨 添加合法性评分可视化显示
- ⚡ 改进指纹采集的 fallback 机制

### 修复 (Fixed)
- 🐛 修复指纹项空值显示问题
- 🐛 修复 N/A 值参与一致性比对的误报
- 🐛 修复设备序列号、型号等基础指纹项为空的问题

---

## [1.1.0] - 2025-01-10

### 新增 (Added)
- ✨ 实现完整的设备指纹采集功能
- ✨ 添加三层数据采集架构（Java/Native/Syscall）
- ✨ 实现指纹数据一致性比对
- ✨ 添加专业的启动页动画
- ✨ 新增应用图标（盾牌主题）

### 改进 (Improved)
- 🎨 重新设计 UI 主题和配色方案
- 🎨 优化启动流程（SplashActivity → MainActivity）
- 📱 改进底部导航栏图标设计

---

## [1.0.0] - 2025-01-08

### 新增 (Added)
- 🎉 项目首次发布
- ✨ 实现环境安全检测功能
  - Root 检测（Magisk/KernelSU/APatch/SukiSU）
  - Hook 检测（Xposed/Frida/LSPosed/ReZygisk）
  - 模拟器检测（夜神/雷电/逍遥等）
  - 调试检测（TracerPid/ptrace/调试端口）
  - 网络检测（VPN/代理/抓包）
- ✨ 实现基础设备信息采集
- ✨ 实现 Native 层核心检测逻辑
- ✨ 实现 Syscall 直接系统调用（ARM64/ARM32）
- 🎨 实现 Material Design 风格 UI
- 📱 实现三个主要页面（环境检测/指纹信息/机型信息）

### 技术栈
- Android SDK 36 (Target)
- Android SDK 28 (Min)
- NDK 25.1.8937393
- CMake 3.22.1
- Gradle 8.13
- Java 11
- C++17

---

## 分类说明

- **新增 (Added)**: 新功能
- **变更 (Changed)**: 既有功能的变更
- **弃用 (Deprecated)**: 即将移除的功能
- **移除 (Removed)**: 已移除的功能
- **修复 (Fixed)**: 任何 bug 修复
- **安全 (Security)**: 修复安全问题
- **改进 (Improved)**: 性能优化、代码重构等

---

## 版本号规则

版本号格式: `主版本号.次版本号.修订号` (MAJOR.MINOR.PATCH)

- **主版本号**: 不兼容的 API 修改
- **次版本号**: 向下兼容的功能性新增
- **修订号**: 向下兼容的问题修正

---

## 计划中的更新

### [1.2.0] - 计划中
- 设备指纹导出功能（JSON/CSV/PDF）
- 检测报告生成
- 自定义检测规则
- 在线更新检测规则
- 更多 2025 年最新 Root 方案检测

### [1.3.0] - 计划中
- Hook 框架绕过测试
- 云手机检测
- 完善 x86 模拟器检测
- 性能优化
- UI/UX 改进

---


<div align="center">

**保持更新，持续改进** 🚀

</div>
