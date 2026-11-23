package yuc;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.BiConsumer;

/**
 * 参数抽取：把一次请求拆成「模板里的参数行」，把请求/响应拆成「参数名清单」。
 * <p>
 * 三件事的规则不一样，所以分成三组方法：
 * <ul>
 *   <li>{@link #templateParams} —— 写进 .json 模板的，必须能被 v3-lite 还原成报文。
 *       所以数组整棵一行（type:array），不展开成 a[0].x，行数才不会爆。</li>
 *   <li>{@link #stats} —— 只给人看的字段清单，数组用 [] 展开成 data.list[].id，便于认结构。</li>
 *   <li>{@link #requestShape} —— 只留参数<b>名字</b>的指纹，判重时用来判断
 *       「长度变了但请求根本没变形」。</li>
 * </ul>
 */
public final class Params {

    /** 请求体最多记这么多字符，避免把大响应 / 二进制写进模板。 */
    public static final int MAX_REQUEST_BODY = 256 * 1024;

    /** multipart 的值超过这么长就换成占位符，别把上传内容糊进模板。 */
    private static final int MAX_MULTIPART_VALUE = 50;

    /** 上传内容过长时的占位符：只占位，不携带内容。 */
    public static final String LONG_VALUE_PLACEHOLDER = "aaaaa-neirongguoda-aaaaaa";

    /** 数组容器的键清单在表格里最多显示这么长（`query` 这种十一二个键就差不多满了）。 */
    private static final int MAX_KEYS_TEXT = 300;

    private Params() {
    }

    // ------------------------------------------------------------ 模板参数行

    public static List<Map<String, Object>> templateParams(Endpoint ep) {
        return templateParams(ep, Set.of());
    }

    /**
     * @param skipCookies 已经写进 {@code base.headers} 的 Cookie 键（{@code name\u0000value}）。
     *                    这些不再逐条重复：一个站一百个接口，Cookie 记一百遍纯属浪费；
     *                    只跳过值也一模一样的，接口用自己的会话时照样留下。
     */
    public static List<Map<String, Object>> templateParams(Endpoint ep, Set<String> skipCookies) {
        List<Map<String, Object>> rows = new ArrayList<>();

        for (String[] q : ep.query) {
            if (!q[0].isEmpty()) {
                rows.add(row("query", q[0], q[1]));
            }
        }
        for (String[] c : ep.cookies) {
            if (!c[0].isEmpty() && !skipCookies.contains(c[0] + '\u0000' + (c[1] == null ? "" : c[1]))) {
                rows.add(row("cookie", c[0], c[1]));
            }
        }

        String ct = lower(ep.requestContentType);
        String body = ep.requestBody == null ? "" : ep.requestBody;
        if (body.isEmpty()) {
            return rows;
        }

        if (ct.contains("json") || looksJson(body)) {
            Object json = MiniJson.tryParse(body);
            if (json == null) {
                rows.add(rawRow(truncate(body), ct));
            } else {
                flatten(json, "", rows);
            }
        } else if (ct.contains("x-www-form-urlencoded")) {
            for (String[] p : Urls.formPairs(body)) {
                if (!p[0].isEmpty()) {
                    rows.add(row("form", p[0], p[1]));
                }
            }
        } else if (ct.contains("multipart/form-data")) {
            // 注意：这里必须传原始头，boundary 是大小写敏感的，转小写就匹配不上了
            rows.addAll(multipartRows(body, ep.requestContentType));
        } else {
            rows.add(rawRow(truncate(body), ct));
        }
        return rows;
    }

    /** JSON 树 → 参数行：对象逐层拆成 a.b，数组整棵塞一行（type:array）。 */
    private static void flatten(Object node, String prefix, List<Map<String, Object>> rows) {
        if (node instanceof Map) {
            Map<?, ?> map = (Map<?, ?>) node;
            if (map.isEmpty() && !prefix.isEmpty()) {
                rows.add(typedRow("json", prefix, new LinkedHashMap<>(), "object"));
                return;
            }
            for (Map.Entry<?, ?> e : map.entrySet()) {
                String key = String.valueOf(e.getKey());
                flatten(e.getValue(), join(prefix, key), rows);
            }
        } else if (node instanceof List) {
            List<?> list = (List<?>) node;
            if (prefix.isEmpty()) {
                // 顶层就是数组：整行给完，name 用空串表示「目标就是请求体本身」
                rows.add(typedRow("json", "", new ArrayList<>(list), "array"));
            } else {
                rows.add(typedRow("json", prefix, new ArrayList<>(list), "array"));
            }
        } else {
            rows.add(row("json", prefix, node));
        }
    }

    private static List<Map<String, Object>> multipartRows(String body, String contentType) {
        List<Map<String, Object>> rows = new ArrayList<>();
        String boundary = "";
        String ctRaw = contentType == null ? "" : contentType;
        int bi = ctRaw.toLowerCase().indexOf("boundary=");
        if (bi >= 0) {
            boundary = ctRaw.substring(bi + 9).trim();
            if (boundary.startsWith("\"")) {
                boundary = boundary.replace("\"", "");
            }
        }
        if (boundary.isEmpty()) {
            return rows;
        }
        for (String part : body.split("--" + java.util.regex.Pattern.quote(boundary))) {
            if (part.isBlank()) {
                continue;
            }
            String name = between(part, "name=\"", "\"");
            if (name.isEmpty()) {
                continue;
            }
            String filename = between(part, "filename=\"", "\"");
            int split = part.indexOf("\r\n\r\n");
            if (split < 0) {
                split = part.indexOf("\n\n");
            }
            String value = "";
            if (split >= 0) {
                value = part.substring(split).replaceFirst("^(\r\n\r\n|\n\n)", "");
                value = value.replaceFirst("(\r\n|\n)$", "");
            }
            if (!filename.isEmpty()) {
                rows.add(typedRow("multipart", name, clipMultipart("./" + filename), "file"));
            } else {
                rows.add(row("multipart", name, clipMultipart(value)));
            }
        }
        return rows;
    }

    /** 上传的值太长（比如整个 base64 文件内容）就只留占位符，模板里不需要真内容。 */
    private static String clipMultipart(String value) {
        if (value == null) {
            return "";
        }
        return value.length() > MAX_MULTIPART_VALUE ? LONG_VALUE_PLACEHOLDER : value;
    }

    private static Map<String, Object> rawRow(String body, String contentType) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("in", "raw");
        m.put("name", "");
        m.put("value", body);
        m.put("mediaType", contentType.isEmpty() ? "application/octet-stream" : contentType.split(";")[0].trim());
        return m;
    }

    /** 普通参数行：类型由值的形状推断，字符串不写 type（v3-lite 允许省略）。 */
    private static Map<String, Object> row(String in, String name, Object value) {
        return typedRow(in, name, value, typeOf(value));
    }

    private static Map<String, Object> typedRow(String in, String name, Object value, String type) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("in", in);
        m.put("name", name);
        Object normalized = normalizeBigInts(value);
        m.put("value", normalized);
        if (value instanceof BigInteger || (value instanceof Number && normalized instanceof String)) {
            // 超过 2^53-1 的整数只有写成字符串才不会掉精度
            m.put("type", "string");
        } else if (type != null) {
            m.put("type", type);
        }
        return m;
    }

    /** 2^53-1：超过这个数，JS/其他语言的解析器就会悄悄改数字。 */
    private static final long MAX_SAFE_INT = 9007199254740991L;

    /** 把一个值里所有超大整数转成字符串（数组、对象一起走），保证落盘的 JSON 不掉精度。 */
    private static Object normalizeBigInts(Object v) {
        if (v instanceof Long || v instanceof Integer || v instanceof Short) {
            long n = ((Number) v).longValue();
            return Math.abs(n) > MAX_SAFE_INT ? String.valueOf(n) : v;
        }
        if (v instanceof BigInteger) {
            return v.toString();
        }
        if (v instanceof Map) {
            Map<String, Object> out = new LinkedHashMap<>();
            for (Map.Entry<?, ?> e : ((Map<?, ?>) v).entrySet()) {
                out.put(String.valueOf(e.getKey()), normalizeBigInts(e.getValue()));
            }
            return out;
        }
        if (v instanceof List) {
            List<Object> out = new ArrayList<>();
            for (Object el : (List<?>) v) {
                out.add(normalizeBigInts(el));
            }
            return out;
        }
        return v;
    }

    private static String typeOf(Object v) {
        if (v == null) {
            return "null";
        }
        if (v instanceof Boolean) {
            return "boolean";
        }
        if (v instanceof Number) {
            return "number";
        }
        if (v instanceof Map) {
            return "object";
        }
        if (v instanceof List) {
            return "array";
        }
        return null; // 字符串：不写，值自己说明了一切
    }

    // ------------------------------------------------------------ 请求形状

    /**
     * 请求参数的「形状」：把 <b>位置 + 名字</b> 排序拼成一个串，用来判断两份样本的请求
     * 是不是同一套参数（值不算，{@code page=1} 与 {@code page=2} 是同一种形状）。
     * <p>
     * 名字带位置前缀（{@code query} / {@code cookie} / {@code json} / {@code form} / {@code multipart}），
     * 否则查询里的 {@code id} 和请求体里的 {@code id} 会算成同一个，形状就比错了。
     * <p>
     * JSON 用完整路径（{@code data.list[].id}）而不是最后一层 key：数组整棵算一个名字，
     * 元素多少不影响形状——「列表从 3 条变 5 条」本来就不该算换了个接口形态。
     *
     * @return 认不出参数名的请求（原始报文、二进制体）返回 {@code null}，
     * 调用方应把它当作「无法比较」，别拿它去判重——宁可多留一档，也别把内容丢了。
     */
    public static String requestShape(Endpoint ep) {
        Set<String> names = new java.util.TreeSet<>();
        for (String[] q : ep.query) {
            if (q[0] != null && !q[0].isEmpty()) {
                names.add("query\u0000" + q[0]);
            }
        }
        for (String[] c : ep.cookies) {
            if (c[0] != null && !c[0].isEmpty()) {
                names.add("cookie\u0000" + c[0]);
            }
        }
        String ct = lower(ep.requestContentType);
        String body = ep.requestBody == null ? "" : ep.requestBody;
        if (body.isEmpty()) {
            return String.join("\n", names);
        }
        if (ct.contains("json") || looksJson(body)) {
            walkKeys(MiniJson.tryParse(body), "", (name, value) -> {
                if (!name.isEmpty()) {
                    names.add("json\u0000" + name);
                }
            });
        } else if (ct.contains("x-www-form-urlencoded")) {
            for (String[] p : Urls.formPairs(body)) {
                if (!p[0].isEmpty()) {
                    names.add("form\u0000" + p[0]);
                }
            }
        } else if (ct.contains("multipart/form-data")) {
            for (Map<String, Object> r : multipartRows(body, ep.requestContentType)) {
                names.add("multipart\u0000" + r.get("name"));
            }
        } else {
            return null; // 原始报文体：没有"参数名"这回事
        }
        return String.join("\n", names);
    }

    // ------------------------------------------------------------ 字段清单

    /** 一个域名下所有接口的字段并集（按 位置+名字 去重）。 */
    public static List<ParamStat> stats(List<Endpoint> endpoints) {
        return stats(endpoints, null);
    }

    /**
     * @param baseHeaders 整站共用的鉴权头（模板 base.headers）。它们对所有接口生效，
     *                    所以每个样本都算一次「用到」，接口数自然等于接口总数。
     */
    public static List<ParamStat> stats(List<Endpoint> endpoints, Map<String, String> baseHeaders) {
        Map<String, ParamStat> index = new LinkedHashMap<>();
        List<String[]> shared = HeaderPolicy.asPairs(baseHeaders);
        for (Endpoint ep : endpoints) {
            for (String[] q : ep.query) {
                add(index, q[0], "查询", q[1], ep);
            }
            for (String[] c : ep.cookies) {
                add(index, c[0], "Cookie", c[1], ep);
            }
            String ct = lower(ep.requestContentType);
            if (ct.contains("json") || looksJson(ep.requestBody)) {
                Object json = MiniJson.tryParse(ep.requestBody);
                walkKeys(json, "",
                        (name, value) -> add(index, name, "请求体", sample(value), full(value), ep));
                // 容器本身也要占一行：walkKeys 只吐叶子，`query` / `where` 这种「整块是一个参数」会漏掉
                walkContainers(json, "", (name, text) ->
                        add(index, name, "请求体", clipContainers(text), text, ep));
            } else if (ct.contains("x-www-form-urlencoded")) {
                for (String[] p : Urls.formPairs(ep.requestBody)) {
                    add(index, p[0], "表单", p[1], ep);
                }
            } else if (ct.contains("multipart/form-data")) {
                for (Map<String, Object> r : multipartRows(ep.requestBody == null ? "" : ep.requestBody, ep.requestContentType)) {
                    add(index, String.valueOf(r.get("name")), "multipart", sample(r.get("value")), ep);
                }
            }
            // 请求头来源：base 里定义的整站头，每个接口都有。
            // 展示值要截断（Cookie 可能几百字符），但 payload 要完整值，否则复制出去是残的
            for (String[] h : shared) {
                add(index, h[0], "请求头", clipHeader(h[1]), h[1], ep);
            }
            // 响应字段：实时样本有正文，从正文里挖；从数据库恢复的样本没有正文，用它存下的字段清单
            if (ep.responseBody != null && !ep.responseBody.isEmpty()) {
                Object json = MiniJson.tryParse(ep.responseBody);
                walkKeys(json, "",
                        (name, value) -> add(index, name, "响应", sample(value), full(value), ep));
                walkContainers(json, "", (name, text) ->
                        add(index, name, "响应", clipContainers(text), text, ep));
            } else {
                for (String[] f : ep.storedFields) {
                    add(index, f.length > 1 ? f[1] : f[0], "响应", f.length > 2 ? f[2] : "", ep);
                }
            }
        }
        List<ParamStat> out = new ArrayList<>(index.values());
        out.sort((a, b) -> {
            int c = Integer.compare(b.endpoints, a.endpoints);
            return c != 0 ? c : a.name.compareTo(b.name);
        });
        return out;
    }

    /** 头值可能很长（Cookie 几百字符），列表里只留个开头。 */
    private static String clipHeader(String value) {
        if (value == null) {
            return "";
        }
        return value.length() > 120 ? value.substring(0, 120) + "…" : value;
    }

    private static void add(Map<String, ParamStat> index, String fullPath, String where, String example, Endpoint ep) {
        add(index, fullPath, where, example, example, ep);
    }

    /**
     * @param full 完整值（不截断），复制 payload 时用；{@code example} 只负责展示
     */
    private static void add(Map<String, ParamStat> index, String fullPath, String where,
                            String example, String full, Endpoint ep) {
        if (fullPath == null || fullPath.isEmpty()) {
            return;
        }
        // 只有 JSON 的「请求体 / 响应」才按路径看最后一层；查询、Cookie、表单的名字是字面量，不能拆
        boolean jsonPath = where.equals("请求体") || where.equals("响应");
        String key = jsonPath ? lastKey(fullPath) : fullPath;
        String id = where + '\u0000' + key;
        ParamStat st = index.get(id);
        if (st == null) {
            st = new ParamStat(key, fullPath, where, example, ep.path);
            index.put(id, st);
        }
        st.keepFull(full);
        st.touch(ep);
    }

    /**
     * 路径只留最后一层：`metadata.schema.properties.size.title` → `title`。
     * 界面上只要 key，层级是模板的事，不用在这儿给人看。
     */
    public static String lastKey(String path) {
        if (path == null || path.isEmpty()) {
            return "";
        }
        String p = path;
        while (p.endsWith("[]")) {
            p = p.substring(0, p.length() - 2);
        }
        // 结尾是 ["..."] 时，键名本身可能带点号，不能按点号切
        if (p.endsWith("\"]")) {
            int open = p.lastIndexOf("[\"");
            if (open >= 0) {
                return p.substring(open + 2, p.length() - 2);
            }
        }
        int dot = p.lastIndexOf('.');
        String key = dot >= 0 ? p.substring(dot + 1) : p;
        if (key.startsWith("[") && key.endsWith("]")) {
            key = key.substring(1, key.length() - 1);
        }
        return key.isEmpty() ? path : key;
    }

    /**
     * 只用于展示的深度遍历：数组统一用 [] 表示，`data.list[].id` 一眼能看出层级。
     * 空数组/空对象也会出现在清单里（它们本身是"有字段"的信号）。
     */
    public static void walkKeys(Object node, String prefix, BiConsumer<String, Object> sink) {
        if (node instanceof Map) {
            Map<?, ?> map = (Map<?, ?>) node;
            if (map.isEmpty() && !prefix.isEmpty()) {
                sink.accept(prefix, null);
            }
            for (Map.Entry<?, ?> e : map.entrySet()) {
                walkKeys(e.getValue(), join(prefix, String.valueOf(e.getKey())), sink);
            }
        } else if (node instanceof List) {
            List<?> list = (List<?>) node;
            String p = prefix + "[]";
            if (list.isEmpty()) {
                sink.accept(p, null);
            }
            for (Object el : list) {
                walkKeys(el, p, sink);
            }
        } else if (!prefix.isEmpty()) {
            sink.accept(prefix, node);
        }
    }

    // ------------------------------------------------------------ 容器行
    /**
     * 只给参数表用的深度遍历：把<b>数组和对象节点本身</b>也报出来，附带它们的键。
     * <p>
     * {@link #walkKeys} 只吐叶子（{@code query[].identifier}），容器自己不会出现在清单里，
     * 于是 {@code {"query":[…],"where":{…}}} 里的 {@code query} / {@code where} 在参数表里
     * 都查不到。这里补的就是这一行，值写成键清单：
     * 数组用 {@code [identifier,select]}（元素里出现过的键），对象用 {@code {condition,logical}}。
     * <p>
     * 为什么对象也要补：它不只是"分层"，换个后端它就是一个正经参数（{@code where} 这种
     * 查询体整块传、后端按对象收），漏掉就查不到「这个接口收不收 where」。
     * <p>
     * 四条边界：
     * <ul>
     *   <li><b>数组元素</b>（{@code query[]} 指到的那个对象）不单独报——它就是数组本身，
     *       已经由数组那一行描述过了，再报一次会和数组行同名打架</li>
     *   <li>空数组 / 空对象不报：没有键可列，写个 {@code []} 反而是错的
     *       （它们自己那条 {@code xxx[]} 叶子行 {@link #walkKeys} 会给）</li>
     *   <li>标量数组（{@code ["a","b"]}）不报：同理，没有键</li>
     *   <li>顶层容器不报：那就是请求体本身，没有参数名</li>
     * </ul>
     * <b>只影响参数表</b>：模板（{@link #templateParams}）、判重形状（{@link #requestShape}）、
     * 落库的参数行都不走这个函数，导出的 json 一个字节都不会变。
     */
    public static void walkContainers(Object node, String prefix, BiConsumer<String, String> sink) {
        walkContainers(node, prefix, false, sink);
    }

    private static void walkContainers(Object node, String prefix, boolean inArray,
                                       BiConsumer<String, String> sink) {
        if (node instanceof Map) {
            Map<?, ?> map = (Map<?, ?>) node;
            if (!inArray && !prefix.isEmpty() && !map.isEmpty()) {
                StringBuilder sb = new StringBuilder("{");
                for (Object k : map.keySet()) {
                    if (sb.length() > 1) {
                        sb.append(',');
                    }
                    sb.append(String.valueOf(k));
                }
                sink.accept(prefix, sb.append('}').toString());
            }
            for (Map.Entry<?, ?> e : map.entrySet()) {
                walkContainers(e.getValue(), join(prefix, String.valueOf(e.getKey())), false, sink);
            }
        } else if (node instanceof List) {
            List<?> list = (List<?>) node;
            Set<String> names = new LinkedHashSet<>();
            for (Object el : list) {
                if (el instanceof Map) {
                    for (Object k : ((Map<?, ?>) el).keySet()) {
                        names.add(String.valueOf(k));
                    }
                }
            }
            if (!inArray && !prefix.isEmpty() && !names.isEmpty()) {
                sink.accept(prefix, "[" + String.join(",", names) + "]");
            }
            for (Object el : list) {
                walkContainers(el, prefix + "[]", true, sink);
            }
        }
    }

    /** 参数表里那格只留开头；复制「参数值」时用的是没截断的那份。 */
    private static String clipContainers(String text) {
        return text.length() > MAX_KEYS_TEXT ? text.substring(0, MAX_KEYS_TEXT) + "…" : text;
    }

    // ------------------------------------------------------------ 小工具

    /** 拼 JSON 路径：普通键用点号，含特殊字符的键用 ["..."]。 */
    static String join(String prefix, String key) {
        boolean simple = !key.isEmpty() && key.chars().allMatch(c ->
                Character.isLetterOrDigit(c) || c == '_' || c == '-' || c == '$');
        String piece = simple ? key : "[\"" + key.replace("\\", "\\\\").replace("\"", "\\\"") + "\"]";
        if (prefix.isEmpty()) {
            return piece;
        }
        return simple ? prefix + "." + piece : prefix + piece;
    }

    static boolean looksJson(String s) {
        if (s == null) {
            return false;
        }
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (Character.isWhitespace(c)) {
                continue;
            }
            return c == '{' || c == '[';
        }
        return false;
    }

    private static String sample(Object v) {
        if (v == null) {
            return "";
        }
        String s = v instanceof Map ? "{...}" : v instanceof List ? "[...]" : String.valueOf(v);
        return s.length() > 120 ? s.substring(0, 120) + "…" : s;
    }

    /**
     * 完整值（不截断）。对象/数组只给个形状，复制 payload 时也用不上整棵树；
     * 标量则原样给，长值（比如 base64）复制出去才是完整的。
     */
    private static String full(Object v) {
        if (v == null) {
            return "";
        }
        return v instanceof Map ? "{...}" : v instanceof List ? "[...]" : String.valueOf(v);
    }

    private static String between(String text, String open, String close) {
        int a = text.indexOf(open);
        if (a < 0) {
            return "";
        }
        int b = text.indexOf(close, a + open.length());
        return b < 0 ? "" : text.substring(a + open.length(), b);
    }

    private static String lower(String s) {
        return s == null ? "" : s.toLowerCase();
    }

    private static String truncate(String s) {
        if (s == null) {
            return "";
        }
        return s.length() > MAX_REQUEST_BODY ? s.substring(0, MAX_REQUEST_BODY) : s;
    }

    /** 供 UI 展示用的一行统计。 */
    public static final class ParamStat {
        /** 展示用的名字：只留最后一层 key。 */
        public final String name;
        /** 第一次见到的完整路径，鼠标悬停时看。 */
        public final String fullPath;
        public final String where;
        public final String example;
        /** 完整值（不截断）。复制 payload 时用它，列表里显示的仍是 {@link #example}。 */
        public String payload;
        /** 出现过这个参数的路径（去重）。 */
        public final Set<String> paths = new LinkedHashSet<>();
        /** 出现过这个参数的接口去重键，用来反查"来源接口"。 */
        public final Set<String> endpointKeys = new LinkedHashSet<>();
        public int endpoints;

        ParamStat(String name, String fullPath, String where, String example, String firstPath) {
            this.name = name;
            this.fullPath = fullPath;
            this.where = where;
            this.example = example == null ? "" : example;
            this.payload = this.example;
            if (firstPath != null) {
                paths.add(firstPath);
                endpoints = 1;
            }
        }

        /** 记住更完整的那个值：同一个参数在不同接口里长短不一，留最长的当样例。 */
        void keepFull(String full) {
            if (full != null && full.length() > payload.length()) {
                payload = full;
            }
        }

        void touch(Endpoint ep) {
            if (ep == null) {
                return;
            }
            paths.add(ep.path);
            endpointKeys.add(ep.key);
            endpoints = endpointKeys.size();
        }
    }
}
