# **冈.易模组自动解包工具**

作者：sneake666(QQ:3767952779)

这是一个用于自动解包冈.易MCP模组（MCPK，后缀名为.mcp）的工具。

该项目基于 vanilla_mcp_util 二次编写(https://github.com/Conla-AC/vanilla_mcp_util)

## 功能特性（相比原版）

- ✅ 对所有输入输出都进行了汉化
- ✅ 无需对mcs一个一个地进行反混淆，可以一键解包到py

## 快速开始
运行main.py，随后根据指引进行操作即可

## 重要的故障排查
如果运行时出现反混淆到mcs正常，但解密为py全部失败，请使用以下命令安装依赖uncompyle6：
```bash
pip install uncompyle6
```
作者将在下一版本加入依赖检查，请稍等
