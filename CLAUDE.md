# CLAUDE.md

本工程是一个 Burp Suite 扩展（Montoya API），扩展名 **yuc**，版本 **1.0**。
作用：被动采集 Proxy / Repeater 里的 JSON 接口，存进 SQLite 并聚合成 v3-lite 模板
（`域名_端口.json`），在 Burp 里提供一个「左边域名树、右边路径 + 参数」的界面，
还能把接口还原到 Repeater（鉴权头来自模板 `base.headers`，其余由全局请求头配置兜底）。

## 架构

| 文件 | 职责 |
|---|---|
| `src/main/java/yuc/YucExtension.java` | 入口，实现 `BurpExtension`；挂 HttpHandler、注册标签页、卸载时 flush |
| `Capture.java` | **判定与组装的唯一出口**：7 个标准方法、`#`、末段含点、记录类型 `kindOf`（JSON / HTML）、空/超大响应、`bodyOf` 取正文，以及 `Endpoint` 拼装 |
| `Settings.java` | 收录范围（黑/白名单 glob）与响应范围（解析上限、字段上限），存 `yuc.db` 的 `settings` 表 |
| `SettingsDialog.java` | 设置页（Swing 弹框）：两个名单框 + 两个上限，文案压到最短（标题一行 + 示例一行） |
| `Recorder.java` | 实时采集，实现 Montoya `HttpHandler`；只读流量，规则全部委托 `Capture` |
| `HistoryImport.java` | 主动补捞：扫 `api.proxy().history()`，规则同样走 `Capture`；带进度与分类统计 |
| `Db.java` | **SQLite 持久化**：`endpoints` + `endpoint_params` + `endpoint_samples` + `endpoint_sample_params` + `domain_headers` + `marks` + `settings` 七张表，整域名重写，启动 `loadAll()`，老库自动补 `lengths` 列 |
| `TemplateImport.java` | 老数据迁移：解析目录里的 `域名_端口.json`，把参数反推回请求体（含嵌套 JSON / 数组 / 大整数） |
| `HeaderProfile.java` | 请求头配置：宽容解析粘贴文本（整段报文/响应/裸 KV），还原时整组替换 |
| `HeaderPolicy.java` | **哪些头进 `base.headers`** 的唯一判定：鉴权关键词白名单 + 缓存/协商/指纹黑名单 + 多值投票 |
| `Payload.java` | 「复制为 payload」的三种格式：raw（不转义）/ json（值当字符串）/ xml（非法标签名退化） |
| `TextFilter.java` | 搜索框的**单条件**匹配：包含 + 忽略大小写 + 正则（正则写错不抛） |
| `SearchRule.java` | **高级搜索**：列 + 关系（12 种，数字列多 4 种）+ 值，`且`优先于`或`；`Field.options` 非空时值改成下拉（颜色） |
| `Marks.java` | **行的颜色标记**：6 色 + 落库（`marks` 表）+ 排序规则 `compare`；路径按去重键、参数按「位置+名字」 |
| `Endpoint.java` | 一个接口样本（不可变）：请求/响应、query、cookie、长度、去重键、DB 恢复来的响应字段；`samples()` 是这个接口的全部长度档 |
| `EndpointStore.java` | 按 `host:port` 分组，组内按响应长度分档（`Group` + `TreeMap`，最多 `MAX_SAMPLES = 8`），1.2s 防抖落盘、设置持久化 |
| `Params.java` | 参数抽取：模板行（数组整棵一行）、界面字段清单（只留最后一层 key + `endpointKeys` 反查）、`requestShape`、容器行 `walkContainers`（数组 `[…]` / 对象 `{…}`） |
| `TemplateBuilder.java` | 生成 v3-lite 的 `base + items`（`base.headers` 只写一次），生成文件名与 item id |
| `Replay.java` | 把 `Endpoint` 还原成 Repeater 可用的 `HttpRequest` |
| `MiniJson.java` | 自带 JSON 解析/序列化，插件零第三方依赖 |
| `Urls.java` | URL 拆解、percent 解码、`looksLikeApi`（末段含点号即静态资源）、`displayPath` 分段截断、`rootDomain`（域名取根域 / IPv4 取 /24） |
| `YucPanel.java` | Swing 主界面：域名树 + 路径表 + 参数表 + 三段搜索开关 + 高级搜索（含排序）+ 来源多选 + 参数反查 + 颜色标记 + 复制/payload/详情/删除/导入 |

数据流：Burp 流量 → `Recorder`（过滤）→ `EndpointStore.add`（去重）→ 防抖写文件 + 通知 UI → `TemplateBuilder` 生成 JSON。

## 关键约定（改代码时别破坏）

1. **去重键** = 方法 + 协议://域名:端口 + 路径 + `?参数名集合（排序）`；**不含参数值**，否则 `/list?page=1` 与 `page=2` 会被当成两个接口。同一去重键下再**按响应长度分档**，且「长度变了但参数形状没变」的不占新档，所以「留最长」只决定谁是主样本，不会把别的档干掉。
2. **过滤规则只写在 `Capture` 里**：未勾选开关（仅实时）/ 非 7 个标准方法 / URL 带 `#` / 路径为 `/` / 末段含 `.` / Content-Type 不含 `json` / 空响应 / 响应不以 `{` `[` 开头 → 全部丢弃。`Recorder` 和 `HistoryImport` 都不许自己再抄一份，否则两边迟早不一致。
3. **模板必须能过 `moban/check_v3lite.py`**：`in: raw` 必须 `name: ""` + `mediaType`；`type: file` 只能出现在 multipart/raw；`in: json` 的数组整棵一行；超过 2^53-1 的整数转字符串 + `type: string`。
4. **multipart 的 boundary 区分大小写**：不要把 Content-Type 整体转小写后再取 boundary。
5. **表单体** 用 `Urls.formPairs`（`+` 当空格），**query** 用 `Urls.queryPairs`（`+` 保持字面量），两者不能混。
6. 采集逻辑跑在 Burp 的线程里，异常必须吞掉，不能影响收发；UI 更新一律 `SwingUtilities.invokeLater` + 600ms 防抖。
7. **参数表只显示最后一层 key**（`Params.lastKey`）：`metadata.schema.properties.size.title` → `title`；
   完整路径留在 `ParamStat.fullPath` 里做悬停提示。查询 / Cookie / 表单的名字是字面量，**不能拆**。
   注意 `["a.b"]` 这种键名带点号的，`lastIndexOf('.')` 会切错，必须先判断结尾是 `"]`。
8. **multipart 的值超过 50 字符一律替换成 `Params.LONG_VALUE_PLACEHOLDER`**（`aaaaa-neirongguoda-aaaaaa`）。
9. **「发送到 Repeater」走 `Endpoint.rawRequestBytes()`**：保留原始头顺序，Host/Content-Length 重算，
   丢掉 Connection/Transfer-Encoding/Proxy-Connection/Expect，请求行用原始 query 串（不从参数表重建）。
10. 路径的「按段截断」只是显示层（`Urls.displayPath` + `YucPanel.visible` 做行映射），
    落盘、还原、复制完整路径都必须用完整路径。
11. **参数反查靠 `ParamStat.endpointKeys`**（`Set<ep.key>`，`touch()` 里累加），不要用"接口数"去猜；
    `YucPanel.paramScopeKeys` 是这个集合的副本，筛选时按 `ep.key` 匹配。
12. **两个「重置」必须功能完整**：路径条的 `resetPathFilters` 要同时清 `pathFilter`、`pathInvert`、
    `pathAdvanced` 和 `paramScopeKeys/paramScopeName`（只清一部分会让人以为按钮坏了）；参数条的
    `resetParamFilters` 要清 `paramFilter`、`paramInvert`、`paramAdvanced` 并 `paramSources.clear()`
    （空集 = 全部来源）。
13. **换域名必须清掉 `paramScopeKeys`**（`reloadDomain` 开头），否则会拿 A 站的接口键去筛 B 站，结果恒为空。
14. **「导入历史」只能读 Proxy history**：Montoya 2026.7 没有读 Logger 面板的 API（`api.logging()` 只写不读），
    能读的只有 `api.proxy().history()` / `api.siteMap()`。Repeater 历史补不回来，只能靠实时采集。
15. **导入历史不受采集开关、也不受采集来源限制**：用户点按钮就是明确要读一遍历史；
    导入的样本一律记 `tool = "Proxy"`（历史本身全是代理流量），这样「来源」列照常筛得到。
    重复点击必须幂等——靠的还是 `EndpointStore.add` 的去重 + 长度分档。
16. 导入跑在 `SwingWorker` 里，按钮文字当进度条（`导入 1200/5400`）；**不要在 EDT 上扫 history**，
    history 上万条时会直接把 Burp 卡住。
17. **请求头拆两半存**：整站共用的鉴权头（`Cookie` / `Authorization` / `X-Api-Key`…）进
    `base.headers` + `domain_headers` 表，**一个域名一份**；其余头（`Accept`/`UA`/缓存类）既不进库也不进模板。
    响应正文不落库（太大），响应字段存在 `endpoint_params`（`location='响应'`）里。
    动表结构时想清楚这三者的分工，别顺手把 headers 全塞回去。
18. **`Endpoint.storedFields` 只放响应字段**：`Params.stats` 里"响应正文为空 → 用 storedFields"这条分支，
    放别的分类进去会被全部标成「响应」。
19. **老数据迁移必须先进 `TemplateImport` 再落盘**：库里空 + 目录有 json → 先备份到 `backup-时间戳/`，
    再读回内存并入库。少了这一步，升级后第一次落盘会把老 json 整份覆盖掉。
20. **自测的 `EndpointStore` 必须钉在临时目录**（`new EndpointStore(api, tempDir)` 或让假 preferences
    返回临时路径）。构造函数会 `loadFromDb()` + 迁移，指到 `~/yuc-output` 就会把用户真实数据重写一遍——
    这个坑真踩过。
21. **query 只有两种来源，别混**：能拿到原始 url 串时**必须原样用**（`Urls.query(url)`，一个字节不改），
    只有在「只有解码后参数表」时才用 `Urls.joinQuery()` 重建。重建时空格是 `%20` **不是** `+`
    （query 里的 `+` 是字面加号），编码用 `Urls.queryEncode`，别用 `formEncode`。
    `Endpoint` 构造器会在「url 没 query 但参数表有」时自动补，`requestTarget()` 里还有一层兜底——
    迁移来的样本曾经因此丢掉全部查询参数，`dev/UrlSmoke.java` 就是为这条守着的。
22. **哪些头进 `base.headers` 只由 `HeaderPolicy` 决定**：`NEVER` 黑名单（传输 / 内容协商 / 缓存 / 指纹）
    + 鉴权关键词白名单，两边都要过。缓存与条件请求头（`Cache-Control` / `If-None-Match` / `ETag` /
    `Pragma` / `Expires` / `X-Cache`…）一律排除——它们天天变，写进模板会让模板失效，还会污染参数统计。
    别在 `TemplateBuilder` 或 `TemplateImport` 里另抄一份判断。
23. **`base.headers` 里的 cookie 不再逐条重复**：`Params.templateParams(ep, skipCookies)` 只跳过
    **名字和值都一致**的 cookie 对。某个接口用自己的 `SID` 时必须保留它的 `in: cookie` 行，
    否则会静默丢掉一份登录态。老 json 读回时 `base.headers` 也要过一遍 `HeaderPolicy`，把历史脏数据滤掉。
24. **「复制为 payload」的 raw 不转义**：值是解码后的样例，打注入时要能直接改，编码一遍就废了；
    json / xml 才做转义。复制取 `ParamStat.payload`（完整值），不是表格里被截断的 `example`。
25. **参数来源是多选集合**（`paramSources`，空集 = 全部），不要再退回单选下拉：
    一个接口同时带 query + Cookie + 表单是常态，单选只能看一类。展示顺序按 `PARAM_SOURCES` 拼，
    因为集合是 `HashSet`，直接迭代会跳序。
26. **同一个接口按响应长度分档，不是一个接口一条记录**：`EndpointStore.Group` 用
    `TreeMap<Long, Endpoint>` 存最多 `MAX_SAMPLES = 8` 档，`lastEntry()` 就是主样本（最长那档）。
    规则是：
    * **同长度来了 → 直接丢**（`skipped++`），**不刷新参数值**——用户明确要"长度变短不更新参数值"
    * **新长度但参数形状已被占 → 也直接丢**（`skipped++`，`Group.shapeTaken`）。长度变了只是响应在抖
      （时间戳、traceId、列表条数），请求根本没变形，不该再占一档
    * 更长的新形状 → 成为主样本，界面参数表 / 导出模板/`endpoints` 表跟着它走
    * 更短的新形状 → 收为副档，**主样本不动**
    * 满 8 档 → 淘汰**最旧的非主样本**（按 `lastSeen` 严格 `<` 比较，撞时间戳时保留已有的），主样本永不淘汰
    * 满了还来更短的新形状 → 直接丢（不值得挤掉现有一档）
    这么设计是因为"响应越长越完整"在"报错页比成功页长"时会翻车：
    `?deptId` 删掉返回全量（更长）、加个无效参数返回报错（更短），单档模型两头都丢信息。
    **「参数形状」= `Params.requestShape`**：查询名 + Cookie 名 + 请求体字段名，带位置前缀、排序后拼串，
    **只比名字不比値**（`page=1` 与 `page=2` 同形状）。三条边界别动：
    ① 认不出名字的（原始报文体）返回 `null` → **不判重**，宁可多留一档也别丢内容；
    ② 长度 `<= 0` 的模板空壳不参与比较，否则会把后来的真样本挡掉；
    ③ JSON 用完整路径（`data.list[].id`），数组整棵算一个名字，列表条数变化不算换形状。
    结果就是 8 档装的是「几种参数形态」（正常 / 少参数全量 / 参数错 / 未登录），不是「几种长度」。
27. **副档只服务"按长度发送到 Repeater"**：`TemplateBuilder` 只吃主样本，所以模板 item 数不按档膨胀；
    但 `Db` 必须把副档整档存下来（`endpoint_samples` + `endpoint_sample_params`，请求体各存各的，
    不能复用主样本那行）。`EndpointStore.flush()` 同时拿 `endpoints`（主样本写 json）和 `groups`（全档写库）。
28. **`Endpoint.samples()` 是自引用列表**：`Group.link()` 把整档列表塞给每档，所以任一档都能拿到兄弟；
    `sampleCount()` 至少返回 1。改动 `Group` 时别忘了重新 `link()`，否则右键菜单只剩一档。
29. **搜索分两层，别再塞中间态**：单条件走 `TextFilter.contains`（包含 + 忽略大小写 + 正则），
    多条件走 `SearchRule`（列 + 关系 + 值，下拉选出来的）。
    `applyFilter` / `refreshParams` 里是把两者 AND 起来、最后统一受「反向」影响
    ——**反向只作用一次、作用在合并结果上**，只翻转文本框的话高级条件会绕过它。
    正则写错不许抛异常（`PatternSyntaxException` → 当作不匹配），搜索框是边打字边编译的。
30. **高级搜索不许退回文本表达式**：用户明确要「选列 → 选关系 → 填值」。
    关系的可选项跟着列走（`Op.numeric()` + `Field.numeric`），换列时若原关系不适用要退回第一项，
    不能硬 `setSelectedItem` 一个列表里没有的值。
31. **两套搜索条必须长得一样、且各占一行**：`过滤[__] ☑忽略大小写 ☐反向 ☐正则 [高级] [重置]`。
    加条件时两边一起加；也别再拆成两行（用户嫌"两行不好看"）。
32. **左树分组默认收起**：`rebuildTree` 只展开 `expandedGroups` 里的分组（搜索时全展开）。
    展开状态靠 `TreeExpansionListener` 记，但 `rebuilding` 期间、以及搜索框非空时收到的事件一律丢弃
    ——`treeModel.reload()` 自己会触发一堆展开/收起事件，不挡住的话状态会乱、清空搜索后全摊开。
33. **IP 走 `/24` 分组、域名走根域**（`Urls.rootDomain`）：IPv4 用 `isIpv4` 严格判定
    （四段、0-255），别放宽成 `127.1` 这种简写，否则 `1.2.3.4.5` 这种真域名会被误判。IPv6 不做聚合。
34. **破坏性操作只放在右键菜单里，且都要先确认**：单条路径（`removeEndpoints` → 整域名重写 json）、
    整个域名（`removeDomain` → 连 `域名_端口.json` 一起删）、整个分组（逐个 `removeDomain`）。
    工具条上**没有「清空」按钮**（用户要求去掉），要清数据走树上右键。
    `confirm()` 在 headless 下**必须返回 false**——自测里绝不会有人点确定，静默删除等于毁数据。
35. **导入只进不覆盖**：`importEndpoints` 遇到已存在的去重键直接跳过（模板样本长度是 0，
    混进真实多档里会白占一档还显示成「0 等2档」）；导入的 `tool` 记 `导入`，
    `byteLabel()` 对 `responseLength <= 0` 显示「模板」而不是 0。
36. **采集来源就是 Burp 的 14 个模块，名字一个不省、也不许有「其他」桶**：
    `EndpointStore.SOURCE_NAMES` 与 `ToolType.values()` 对齐，`Recorder.toolName` 直接返回
    `type.toolName()`。压缩成「其他」等于把 `Extensions` / `Burp AI` 的流量藏起来，用户勾不准。
    按钮文字也不缩写（不写「3 项」）。空集 = 全部，和参数来源同一套语义。
37. **颜色标记是本地批注，不许进模板**：存在单独的 `marks` 表，**故意不参加 `saveDomain` 的
    整域名重写**（否则每落盘一次颜色全没）。路径键 = `dedupe_key` + scope `域名:端口`（删域名好收），
    参数键 = `位置\0名字`、scope 空串（参数表本来就是跨域名的聚合视图，`Marks.paramTarget` 统一拼）。
    排序规则只有 `Marks.compare` 一份：默认只分「有色/无色」（返回 0 让稳定排序保原序），
    升/降按色号、**无色永远垫底**。
38. **颜色不是表格的一列，所以「按颜色排序」只能放在高级搜索弹框里**（用户明确要求）；
    `[重置]` 必须把排序一起拉回默认（= 有色置顶），表头点击排序保持 JTable 原生行为不管它。
    行底色走 `Marks.tint(色号, 表格底色)` 现算，别写死 `new Color(0xFFEBEE)`——深色主题下会看不见字。
    渲染器包在原有渲染器外面（对齐方式不能变），且**选中行一律不染色**（否则看不出选中）。
39. **记录类型只有 JSON / HTML 两种，默认只记 JSON**：`Capture.kindOf(Content-Type)` 认不出就返回
    `null`（图片、css、js 一律不进，跟开关无关）；`EndpointStore.recordTypes` 空集**退回只 JSON**，
    不做「空 = 全部」——两个都不勾等于一条都不记，是纯坑。勾上 HTML 后必须同时绕过两条只对 JSON
    成立的规则：`Urls.looksLikeApi`（末段含点号）与 `Params.looksLikeJson` 的正文形状校验，
    否则 `.html` 页面还是会被挡掉。顺序也是死规矩：**先判响应类型和开关，再判路径**——
    否则一个图片请求会因为路径好看而白进一遍解析。

40. **容器行（数组 / 对象）只给参数表看，一行都不许进模板**：`walkKeys` 只吐叶子，
    `{"query":[…],"where":{…}}` 里的 `query` / `where` 会整条消失，所以 `Params.walkContainers`
    单独补一行，值写成键清单——数组 `[identifier,select]`、对象 `{condition,logical}`，两类括号要能分清。
    边界：**数组元素那个对象不重复补**（`query[]` 就是数组本身，再报会和 `query` 同名打架）；
    空容器、标量数组、顶层容器都不补（空容器自己那条 `xxx[]` 叶子行 `walkKeys` 会给）。
    **这个函数只能在 `Params.stats` 里调**——`templateParams`（导出的 json）、`requestShape`（判重）、
    `Db.paramRows`（落库）一旦走了它就同时污染模板、判重和旧数据。
    容器行不单独存库：原料是 `request_body`，重启后重算即可。参数表右键「复制参数值」取
    `ParamStat.payload`（完整值），不能用表格里那个截断过的 `example`。

41. **收录范围与响应上限只有一份实现，界面和落库必须用同一个数**：`Settings` 里
    `allows(host,path)` 决定收不收，`maxResponseFields` 同时传给 `Db.saveDomain` 和
    `Params.stats`——只改一边会出现"库里 500 行、界面 1000 行"的错位。
    glob 语义：`*` 任意串、`?` 单字符，**以 `/` 开头匹配路径、否则匹配 host**；
    白名单为空 = 不过滤，非空 = 只收命中的，黑名单永远优先。默认黑名单 8 条
    （google/github/shodan/fofa/adblockplus/bing/gov/edu）——这些站量大、占地方、学不到东西。
    名单第一次运行才预置：用户清空后存的是空串，**不要再回填默认值**（`read()==null` 才给默认）。
    上限只对之后写入生效（整域名重写时才用新值），文档里必须写清楚，否则用户会以为没生效。
    持久化在 `yuc.db.settings` 表（不是 Burp preferences）：换机器拷库即带走；
    `saveDomain` 的整域名重写和 `clearAll()` 都**不许**碰 `settings` 与 `marks`。

## 构建与测试

```bash
bash build.sh          # 产物 build/libs/yuc-1.0.jar
bash build.sh test     # 构建 + dev/ 下 11 个离线自测（不需要 Burp）
```

* 本机 `services.gradle.org` 不通，`./gradlew` 会卡下载；`build.sh` 会自动退回 cache 里的 Gradle 8.14.3。
* JDK 21（`JAVA_HOME`）；montoya-api 2026.7 为 `compileOnly`，不打进 jar。
* 自测共 631 项断言：`dev/Harness.java`（解析/规则/模板/落盘/数组与对象容器行）、`dev/RecorderSmoke.java`（实时采集规则 + 记录类型 JSON/HTML）、`dev/HistorySmoke.java`（伪造 Proxy history + 开 HTML 后补捞）、`dev/DbSmoke.java`（SQLite 持久化 + 老 json 迁移 + 重启后容器行）、`dev/HeaderSmoke.java`（请求头解析与替换）、`dev/UrlSmoke.java`（还原时 query 保真）、`dev/PayloadSmoke.java`（三种 payload 格式）、`dev/BaseHeaderSmoke.java`（`base.headers` 全链路）、`dev/SamplesSmoke.java`（长度 + 参数形状双判重、`lengths` 列、重启后各档不串）、`dev/RulesSmoke.java`（设置页规则：glob / 默认黑名单 / 白名单 / 上限钳制 / 字段上限双端一致）、`dev/FilterSmoke.java`（单条件 + 高级条件 12 种关系 / 颜色列 / IP 分组 / 删除 / 导入 / 颜色标记落库与排序）、`dev/UiSmoke.java`（headless 界面、三开关搜索、高级搜索、按长度发送菜单、树的展开状态、颜色置顶/染色/右键菜单、类型按钮文字、复制参数值）。
* classpath 里要带 `sqlite-jdbc`（`build.sh` 会自动找 gradle 缓存里的 jar）；jar 任务会把 native 一起解包。

## 在 Burp 里加载

`Extensions → Installed → Add` → 类型 Java → 选 `build/libs/yuc-1.0.jar`。
默认不采集，需在 `Yuc` 标签页勾「开始采集」。

## 已知边界

`base.headers` 只收鉴权头（缓存/协商/指纹类一律不收）、非标准方法跳过、路径参数不模板化、
数组只留整棵、一份模板一个 host、>4MB 响应不解析字段、multipart 文件用 `./文件名` 占位、
同一接口最多留 8 档（长度变了 **且** 请求参数名变了才算新档；再多就淘汰最旧的副档，主样本永不淘汰）。

> `moban/`（在 `D:\workbuddy\11\moban`，不在本工程内）的 schema 与 `check_v3lite.py` 已支持
> `base.headers`（规则 R7：拦 Host / Content-Length / Content-Type 这类头，渲染时铺上去并与
> `in: cookie` 合并成一行）。改模板格式时两边要一起改，否则还原出来会丢登录态。
