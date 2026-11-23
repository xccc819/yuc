# yuc

> Burp Suite 插件：被动采集经过 Proxy / Repeater 的接口，拆成参数表存进 SQLite，
> 再导出成可以直接还原成请求的 v3-lite 模板（`域名_端口.json`）。

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
![Java](https://img.shields.io/badge/Java-21-orange)
![Montoya API](https://img.shields.io/badge/Montoya%20API-2026.7-blue)

它解决的是测试过程中最琐碎的那部分：

- **不知道参数叫什么** —— 接口一进来就拆好了，query / Cookie / JSON 体里的参数都在表里，直接拿去 fuzz；
- **想扩大战果** —— 参数表是跨接口聚合的，点一个 `userId` 就能反查全站哪些接口在用它；
- **复测找不到原请求** —— 右键「发送到 Repeater」，靠存档的参数和整站鉴权头还原成当初那条请求；
- **关掉 Burp 就丢** —— 数据落在本地 SQLite，重启、卸载重装都还在。

不做主动发包、不重放、不扫描，只挂一个 `HttpHandler` 旁听。

## 功能

| | |
|---|---|
| 采集 | 来源可多选（Burp 14 个模块）、类型可勾 JSON / HTML（HTML 默认关）、可主动补捞 Proxy 历史 |
| 参数 | query / Cookie / 请求体（JSON · 表单 · multipart · raw）/ 响应字段，按「位置 + 最后一层 key」聚合，可反查来源接口 |
| 容器 | 数组、对象节点本身也占一行，值写成键清单（`[identifier,select]` / `{condition,logical}`），只用于浏览，不进模板 |
| 样本 | 同一接口按响应长度留最多 8 档，长度变了还要比请求参数形状；主样本取最长那档 |
| 浏览 | 域名树（根域 / IP 按 /24 收起，默认折叠）、路径分段截断、忽略大小写 / 反向 / 正则 / 高级条件（列 + 关系 + 值） |
| 标注 | 路径、参数都能标 6 色，存库重启还在；按颜色排序在高级搜索里 |
| 输出 | 每域名一份 `域名_端口.json`，鉴权头收进 `base.headers` 只写一次；发送到 Repeater 时套用 |

## 快速开始

需要 **JDK 21**（Burp 2024 之后的 Montoya API 要求）。

```bash
bash build.sh          # 产物 build/libs/yuc-1.0.jar（内嵌 sqlite-jdbc，约 9.9 MB）
bash build.sh test     # 自测，576 项断言
```

脚本在访问不了 `services.gradle.org` 时会自动退回本机缓存的 Gradle 8.14.3；
也可以直接用 `./gradlew jar`。

加载：Burp → `Extensions → Installed → Add`，类型选 **Java**，选 `yuc-1.0.jar`。

数据目录默认 `~/yuc-output/`（可在界面里改）：`yuc.db` 是库，`域名_端口.json` 是导出的模板。
**响应正文不落库**，只留拆出来的字段。

## 文档

界面每个控件、采集规则、8 档去重、六张表、还原规则、常见问题，见随 Release 附带的使用说明。
开发约定与模块分工见 [CLAUDE.md](CLAUDE.md)。

## 目录

```
src/main/java/yuc/    插件源码（Capture 判定唯一出口、EndpointStore 内存索引、Db 持久化、YucPanel 界面）
dev/                  headless 自测（11 组，不依赖 Burp 界面）
build.sh              构建 + 自测脚本
```

## 已知边界

- 读不到 Burp 的 Logger 面板，只能读 Proxy history；Repeater 的流量靠实时采集。
- 响应正文不存，重启后详情窗口里看不到响应体（字段清单还在）。
- 不管理登录态：`base.headers` 里的 token 过期了，去「请求头配置」换一份。

## 协议

[MIT](LICENSE)。项目基于 PortSwigger 的 [Java extension template](https://github.com/PortSwigger/extension-template) 起步，感谢。
