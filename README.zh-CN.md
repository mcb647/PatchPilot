# PatchPilot

[English](README.md) | **简体中文**

**追踪 Python 改动的影响范围。**

PatchPilot 帮助开发者和 AI Coding Agent 看清这次改了什么、哪些代码可能受影响、哪些测试值得先跑。每条线索都可以追溯到相关文件和行号，分析报告保存在本地。

## 快速开始

需要 Python 3.11+ 和 Git。在 PatchPilot 仓库目录安装。

```sh
python -m pip install .
```

进入要分析的 Git 仓库，执行以下命令。

```sh
patchpilot analyze
patchpilot web
```

打开[本地控制台](http://127.0.0.1:8765/)，可以看本次报告、查历史或发起新分析。在影响图中点击连线，可以看到具体的调用位置。项目设置可以在控制台里修改，也可以用 `patchpilot init` 创建配置文件。

## 选择分析范围

| 想检查什么 | 命令 |
| --- | --- |
| 相对 `HEAD` 的全部本地改动 | `patchpilot analyze` |
| 只看已暂存的改动 | `patchpilot analyze --staged` |
| 只看未暂存的改动 | `patchpilot analyze --working-tree` |
| 当前分支从 `main` 分出后已提交的改动 | `patchpilot analyze --base main` |
| 最近一次提交 | `patchpilot analyze --commit HEAD` |
| 两个提交或引用之间的差异 | `patchpilot analyze --range A..B` |

## 怎么看结果

- **文件变更**告诉你哪些行、函数和类改了。
- **影响线索**告诉你哪些调用方或依赖方值得核对。动态调用可能无法解析，报告会提示分析范围和限制。
- **测试建议**帮助你决定先跑什么。优先看有明确调用链的测试，名称或导入匹配可以作为补充线索。

测试由你或 Agent 执行。代码行为有没有变化，要结合实际测试结果判断。

## 配合 Coding Agent 使用

安装 CLI 后，按宿主的方式安装 [PatchPilot Skill](skills/patchpilot/SKILL.md)。改完 Python 代码后，可以直接让 Agent 检查「这次改动可能影响哪里，应该先跑哪些测试」。

自动化可以读取 JSON，也可以把已保存的报告导出为 Markdown。

```sh
patchpilot analyze --format json
patchpilot history
patchpilot show RUN_ID --format markdown
```

## 本地数据

控制台仅监听本机，报告存入本地 SQLite。报告可能包含代码差异片段。若只想留存元数据，可将 `storage.evidence_mode` 设为 `metadata_only`。

基础静态分析无需模型或 API Key。配置 Judge 服务并为当前分析显式开启后，选取的代码证据可能会发送给该服务。

## 许可证

[MIT](LICENSE)
