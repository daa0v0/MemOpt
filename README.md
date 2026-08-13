# MemOpt

轻量级 Windows 内存优化工具，使用纯 C + Win32 API 开发，无运行时依赖。

## 功能

- **实时监控**：物理内存、页面文件、系统工作集三张卡片可视化展示
- **一键清理**：通过 Native API 清理工作集、文件缓存、修改页列表、备用页列表等
- **后台自动清理**：可配置内存阈值和清理间隔，自动触发保守/强力清理
- **系统托盘**：托盘图标实时显示内存占用百分比，右键菜单快捷操作
- **开机自启**：可选开机自动启动

## 技术细节

- 纯 C + Win32 API，无第三方 UI 框架依赖
- 自绘 UI 控件（卡片、进度条、复选框、Spinner、状态条）
- 内存清理基于 `NtSetSystemInformation` Native API
- 支持 Win8+ 的 `SystemFileCacheInformationEx` 修复旧版 API 兼容性问题
- 逐进程 `SetProcessWorkingSetSize` + `EmptyWorkingSet` 组合释放
- 编译器：MinGW-w64 (GCC)

## 编译

```bash
# 编译资源文件
windres memopt.rc -O coff -o memopt_rc.o

# 编译主程序
gcc -O2 -municode -mwindows memopt.c memopt_rc.o \
    -lpsapi -lshlwapi -lshell32 -luser32 -lgdi32 -ladvapi32 -lcomctl32 \
    -o memopt.exe
```

## 文件说明

| 文件 | 说明 |
|------|------|
| `memopt.c` | 主程序源代码 |
| `memopt.rc` | Windows 资源文件（图标等） |
| `memopt.ico` | 应用图标 |

## 致谢

项目初版源自 [lby123165](https://github.com/lby123165)，在此基础上进行了 UI 重构、内存优化增强和功能完善。

## License

MIT
