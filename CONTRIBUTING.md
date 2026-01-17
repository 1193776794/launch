# 贡献指南 (Contributing Guide)

首先，感谢你考虑为 Launch 项目做出贡献！🎉

本文档提供了如何为项目做出贡献的指南。请在提交 Issue 或 Pull Request 前仔细阅读。

---

## 📋 目录

- [行为准则](#行为准则)
- [如何贡献](#如何贡献)
  - [报告 Bug](#报告-bug)
  - [提出新功能](#提出新功能)
  - [提交代码](#提交代码)
- [开发指南](#开发指南)
  - [环境搭建](#环境搭建)
  - [代码规范](#代码规范)
  - [测试要求](#测试要求)
- [提交规范](#提交规范)
- [文档贡献](#文档贡献)

---

## 🤝 行为准则

本项目采用贡献者公约（Contributor Covenant）行为准则。参与本项目即表示你同意遵守其条款。

### 我们的承诺
- 尊重不同观点和经验
- 接受建设性批评
- 关注对社区最有利的事情
- 对其他社区成员保持同理心

---

## 🎯 如何贡献

### 报告 Bug

在报告 Bug 前，请先：
1. 检查 [Issues](https://github.com/your-repo/launch/issues) 是否已有相关报告
2. 尝试复现问题
3. 收集必要的信息

#### Bug 报告模板

```markdown
## Bug 描述
简要描述遇到的问题

## 复现步骤
1. 打开应用
2. 点击 xxx
3. 看到 xxx 错误

## 预期行为
描述你期望发生什么

## 实际行为
描述实际发生了什么

## 环境信息
- Android 版本: [如 Android 14]
- 设备型号: [如 Xiaomi 14]
- App 版本: [如 v1.1.2]
- CPU 架构: [如 arm64-v8a]

## 截图/日志
如果可能，提供截图或 logcat 日志

## 其他信息
其他相关信息
```

### 提出新功能

我们欢迎新功能建议！在提交前请：
1. 检查是否已有类似建议
2. 确保功能符合项目目标
3. 说明功能的使用场景

#### 功能请求模板

```markdown
## 功能描述
简要描述你希望添加的功能

## 使用场景
描述该功能的使用场景和价值

## 建议实现方案
如果有想法，可以描述建议的实现方式

## 替代方案
是否有其他可行的替代方案

## 其他信息
其他相关信息
```

### 提交代码

#### 流程概述

1. **Fork 项目**
   ```bash
   # 在 GitHub 上点击 Fork 按钮
   ```

2. **克隆仓库**
   ```bash
   git clone https://github.com/your-username/launch.git
   cd launch
   ```

3. **创建特性分支**
   ```bash
   git checkout -b feature/your-feature-name
   # 或
   git checkout -b fix/your-bug-fix
   ```

4. **进行修改**
   - 编写代码
   - 添加测试
   - 更新文档

5. **提交更改**
   ```bash
   git add .
   git commit -m "feat: add amazing feature"
   ```

6. **推送到远程**
   ```bash
   git push origin feature/your-feature-name
   ```

7. **创建 Pull Request**
   - 前往 GitHub 仓库页面
   - 点击 "New Pull Request"
   - 填写 PR 描述

#### Pull Request 检查清单

在提交 PR 前，请确保：

- [ ] 代码符合项目代码规范
- [ ] 已添加必要的注释
- [ ] 已更新相关文档
- [ ] 通过所有测试
- [ ] 没有引入新的警告
- [ ] 提交信息符合规范
- [ ] 已在多种设备/架构上测试（如可能）

---

## 💻 开发指南

### 环境搭建

#### 必需工具
- Android Studio Electric Eel (2022.1.1) 或更高
- JDK 11+
- Android SDK API 28-36
- NDK 25.1.8937393+
- CMake 3.22.1+

#### 构建项目
```bash
# 克隆项目
git clone https://github.com/your-repo/launch.git
cd launch

# 使用 Android Studio 打开项目
# 或命令行构建
./gradlew clean assembleDebug
```

### 代码规范

#### Java 代码规范

```java
// 使用标准 Java 命名约定
public class RootDetector {
    // 常量: 大写 + 下划线
    private static final String LOG_TAG = "RootDetector";

    // 成员变量: 驼峰命名
    private Context context;

    // 方法: 驼峰命名，动词开头
    public boolean checkMagisk() {
        // 实现
    }

    // 注释: 使用 Javadoc
    /**
     * 检测 Magisk 是否存在
     * @return true 如果检测到 Magisk
     */
    public boolean detectMagisk() {
        // 实现
    }
}
```

#### C++ 代码规范

```cpp
// 使用 snake_case 命名
bool check_su_binary() {
    // 实现
}

// 常量: 大写 + 下划线
const char* SU_PATHS[] = {
    "/system/bin/su",
    "/system/xbin/su"
};

// 函数注释
/**
 * Check if file exists using syscall
 * @param path File path to check
 * @return true if file exists
 */
bool syscall_file_exists(const char* path) {
    return syscall_access(path) == 0;
}
```

#### 代码格式化

- Java: 使用 Android Studio 默认格式（Google Java Style）
- C++: 使用 clang-format
- 缩进: 4 空格（Java/C++）
- 行宽: 100 字符

### 测试要求

#### 单元测试
- 为新功能编写单元测试
- 确保测试覆盖率 > 70%

#### 测试设备
尽可能在以下环境测试：
- ✅ 真机（至少 1 台）
- ✅ 模拟器
- ✅ 不同 Android 版本（9.0 - 15.0）
- ✅ 不同 CPU 架构（ARM64/ARM32/x86/x86_64）

#### 测试检查项
- [ ] 功能正常工作
- [ ] 没有崩溃
- [ ] 没有内存泄漏
- [ ] 没有 ANR
- [ ] UI 响应流畅

---

## 📝 提交规范

### Commit Message 格式

使用 [Conventional Commits](https://www.conventionalcommits.org/) 规范：

```
<类型>(<范围>): <简短描述>

<详细描述>

<footer>
```

#### 类型 (Type)
- `feat`: 新功能
- `fix`: 修复 Bug
- `docs`: 文档更新
- `style`: 代码格式调整（不影响功能）
- `refactor`: 代码重构
- `perf`: 性能优化
- `test`: 测试相关
- `chore`: 构建/工具链相关
- `ci`: CI/CD 相关

#### 范围 (Scope)
- `root`: Root 检测相关
- `hook`: Hook 检测相关
- `emulator`: 模拟器检测相关
- `fingerprint`: 指纹采集相关
- `legitimacy`: 合法性检测相关
- `ui`: UI 相关
- `native`: Native 层相关
- `syscall`: Syscall 层相关

#### 示例

```bash
# 新功能
git commit -m "feat(root): add SukiSU detection support"

# Bug 修复
git commit -m "fix(fingerprint): fix N/A value comparison issue"

# 文档更新
git commit -m "docs: update README with x86 support info"

# 重构
git commit -m "refactor(native): refactor syscall wrapper implementation"
```

---

## 📚 文档贡献

### 文档类型

- **README.md**: 项目介绍和快速开始
- **CHANGELOG.md**: 版本更新日志
- **CLAUDE.md**: 项目详细设计文档
- **API 文档**: 代码注释（Javadoc/Doxygen）
- **Wiki**: 使用指南、原理解析等

### 文档规范

- 使用 Markdown 格式
- 中英文混排时注意空格
- 提供代码示例
- 添加必要的截图

### 示例：API 文档

```java
/**
 * 检测设备是否存在 Magisk
 *
 * <p>通过以下方式检测：
 * <ul>
 *   <li>检测 Magisk 相关文件</li>
 *   <li>检测挂载点</li>
 *   <li>检测进程特征</li>
 * </ul>
 *
 * @return {@code true} 如果检测到 Magisk，否则返回 {@code false}
 * @throws SecurityException 如果没有必要的权限
 * @see #checkKernelSU()
 * @since 1.0.0
 */
public boolean checkMagisk() {
    // 实现
}
```

---

## 🎨 贡献方向

欢迎在以下方向做出贡献：

### 核心功能
- 🛡️ 添加新的 Root/Hook 检测方法
- 🔐 完善设备指纹采集
- 📱 支持更多厂商/机型
- 🌐 网络检测增强

### 性能优化
- ⚡ 减少检测耗时
- 💾 降低内存占用
- 🔋 优化电量消耗

### UI/UX
- 🎨 界面美化
- 📊 数据可视化
- 🌍 国际化支持

### 文档
- 📝 完善 API 文档
- 📖 编写使用教程
- 🔬 原理分析文章

### 工具
- 🔧 开发辅助工具
- 🧪 自动化测试
- 📦 CI/CD 优化

---

## 🏆 贡献者

感谢所有为本项目做出贡献的开发者！

<a href="https://github.com/your-repo/launch/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=your-repo/launch" />
</a>

---

## 💬 获取帮助

如果你在贡献过程中遇到问题：

1. 查看 [Wiki](https://github.com/your-repo/launch/wiki)
2. 搜索 [Issues](https://github.com/your-repo/launch/issues)
3. 在 Issues 中提问
4. 联系维护者
   - 微信: xx1193776794
   - 邮箱: 1193776794@qq.com

---

## 📄 许可

提交的代码将遵循项目的开源协议。

---

<div align="center">

**感谢你的贡献！** 🙏

每一个贡献都让项目变得更好 ✨

</div>
