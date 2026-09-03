# Changelog

所有值得注意的变更都会记录在此文件。格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)。

## [1.1.0] - 2026-09-03

### 新增

- **日志轮转**：`memopt.log` 超过 512KB 时自动归档为 `memopt.log.old`，防止长时间运行日志无限膨胀。
- **单实例保护**：启动时创建 `Local\MemOpt_SingleInstance` 互斥锁，防止双开导致两个清理线程并发调用内核内存 API；已有实例时 GUI 弹提示、命令行静默退出。
- **DPI 感知**：Win10 1703+ 使用 `Per-Monitor V2`，回退到 `SystemAware`，旧系统再回退 `SetProcessDPIAware`，高分屏下自绘 UI 不再被系统位图拉伸变模糊。
- **启动横幅日志**：每次启动记录内存占用、阈值、间隔、强力模式、后台自动、管理员权限等关键状态，方便日志定位。

### 改进

- **NTSTATUS 错误码中文说明**：日志中常见错误码（如 `0xC0000061`、`0xC0000003`、`0xC0000004`）现在附带中文解释，一眼区分“权限不足”还是“系统不支持”。
- **设置窗口数字输入框视觉优化**：
  - 去掉 EDIT 控件默认 3D/实线边框，与 spinner 白底融为一体；
  - 数字改用常规字重字体，不再又粗又显眼；
  - 输入框高度缩小并垂直居中，增加左右呼吸空间；
  - `％` / `分钟` 标签右移，不再紧贴输入框；
  - 按压 spinner 时外框高亮蓝色反馈，箭头改用小号字体。

### 维护

- 删除 `SettingsProc` 中永不触达的死代码分支（自定义控件已走子类化，父窗口不会收到对应 `WM_LBUTTONDOWN`）。
- 删除废弃函数 `sync_settings_to_ui_unused`。
- 更新 `README.md` 功能列表与技术细节说明。

### 安全说明

本次所有改动均为外围优化，**未触碰清理核心逻辑**：

- `CLEAN_STEP_DELAY_MS` 150ms 步间延迟保持不变；
- 清理互斥锁 `CLEAN_LOCK_TRY / CLEAN_UNLOCK` 保持不变；
- 区域掩码、安全闸门、Native API 调用顺序保持不变。

## [1.0.0] - 2026-08-13

### 新增

- 初版 MemOpt：轻量级 Windows 内存清理工具。
- 实时监控：物理内存、页面文件、系统工作集可视化卡片。
- 一键清理：基于 `NtSetSystemInformation` 清理工作集、文件缓存、修改页列表、备用页列表等。
- 后台自动清理：可配置阈值与间隔，保守/强力模式。
- 系统托盘：图标实时显示内存占用百分比，右键快捷操作。
- 开机自启选项。

[1.1.0]: https://github.com/daa0v0/MemOpt/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/daa0v0/MemOpt/releases/tag/v1.0.0