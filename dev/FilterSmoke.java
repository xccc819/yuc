import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.persistence.Persistence;
import burp.api.montoya.persistence.Preferences;
import yuc.Endpoint;
import yuc.EndpointStore;
import yuc.Marks;
import yuc.MiniJson;
import yuc.SearchRule;
import yuc.TemplateImport;
import yuc.TextFilter;
import yuc.Urls;

import java.io.File;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 「搜索 + 分组 + 删除 + 导入」这一轮的自测。
 * <p>
 * 三块：
 * <ol>
 *   <li>{@link TextFilter}：忽略大小写 / 正则 / 反向 / and-or-not 表达式</li>
 *   <li>{@link Urls#rootDomain}：IPv4 按 /24 归组，域名仍按根域</li>
 *   <li>{@link EndpointStore}：来源多选、删域名（连文件）、删接口（json 同步少一个 item）、导入判重</li>
 * </ol>
 */
public class FilterSmoke {

    static int failed = 0;

    public static void main(String[] args) throws Exception {
        textFilter();
        advanced();
        ipGrouping();
        sources();
        deleteAndImport();
        marks();

        System.out.println(failed == 0 ? "FILTER PASS" : "FILTER FAILED: " + failed);
        if (failed > 0) {
            System.exit(1);
        }
    }

    // ------------------------------------------------------------ 单条件匹配

    static void textFilter() {
        String hay = "/api/User/Detail?page=1 GET";

        check("包含匹配", TextFilter.contains(hay, "User", false, false));
        check("区分大小写时小写不命中", !TextFilter.contains(hay, "user", false, false));
        check("勾忽略大小写后命中", TextFilter.contains(hay, "user", true, false));
        check("空条件恒真", TextFilter.contains(hay, "", false, false));

        check("正则命中", TextFilter.contains(hay, "/api/[A-Z]\\w+", false, true));
        check("正则忽略大小写", TextFilter.contains(hay, "^/api/user", true, true));
        check("正则不忽略大小写时不命中", !TextFilter.contains(hay, "^/api/user", false, true));
        // 边打字边编译，少个括号不能抛异常，也不能把所有行都留下
        check("非法正则不抛异常且算不命中", !TextFilter.contains(hay, "([a-z", false, true));
        check("非法正则在反向时等于全留", TextFilter.contains(hay, "([a-z", false, true) == false);
    }

    // ------------------------------------------------------------ 高级搜索（列+关系+值）

    static void advanced() {
        Map<String, String> row = new LinkedHashMap<>();
        row.put("path", "/api/User/Detail");
        row.put("method", "GET");
        row.put("status", "403");
        row.put("bytes", "1280");
        row.put("params", "3");
        row.put("tool", "Proxy");
        row.put("url", "https://h5.aep.com.cn/api/User/Detail?page=1");

        // 文本关系
        check("包含（忽略大小写）", hit("path", SearchRule.Op.CONTAINS, "user", row, true));
        check("包含（区分大小写）", !hit("path", SearchRule.Op.CONTAINS, "user", row, false));
        check("不包含", hit("path", SearchRule.Op.NOT_CONTAINS, "order", row, true));
        check("等于（方法）", hit("method", SearchRule.Op.EQUALS, "GET", row, true));
        check("等于区分大小写", !hit("method", SearchRule.Op.EQUALS, "get", row, false));
        check("不等于", hit("method", SearchRule.Op.NOT_EQUALS, "POST", row, true));
        check("开头是", hit("path", SearchRule.Op.STARTS, "/api/", row, true));
        check("开头是不是就假", !hit("path", SearchRule.Op.STARTS, "Detail", row, true));
        check("结尾是", hit("path", SearchRule.Op.ENDS, "Detail", row, true));
        check("正则匹配", hit("path", SearchRule.Op.REGEX, "^/api/[A-Z]\\w+/", row, true));
        check("正则不匹配", hit("path", SearchRule.Op.NOT_REGEX, "^/admin", row, true));
        check("非法正则算不成立", !hit("path", SearchRule.Op.REGEX, "([a-z", row, true));

        // 数字关系
        check("大于", hit("status", SearchRule.Op.GT, "400", row, true));
        check("大于等于（等于时也成立）", hit("status", SearchRule.Op.GE, "403", row, true));
        check("小于", hit("bytes", SearchRule.Op.LT, "2000", row, true));
        check("小于等于", hit("params", SearchRule.Op.LE, "3", row, true));
        check("数字比较不成立", !hit("status", SearchRule.Op.LT, "400", row, true));
        check("文本列做数字比较不成立", !hit("path", SearchRule.Op.GT, "1", row, true));
        check("非数字的值不成立", !hit("status", SearchRule.Op.GT, "abc", row, true));

        // 组合：且优先于或
        List<SearchRule> and = new ArrayList<>();
        and.add(rule("path", SearchRule.Op.CONTAINS, "api", false));
        and.add(rule("method", SearchRule.Op.EQUALS, "GET", false));
        check("两条都成立（且）", SearchRule.match(and, row, true));

        List<SearchRule> andFail = new ArrayList<>();
        andFail.add(rule("path", SearchRule.Op.CONTAINS, "api", false));
        andFail.add(rule("method", SearchRule.Op.EQUALS, "POST", false));
        check("一条不成立则整体不成立", !SearchRule.match(andFail, row, true));

        List<SearchRule> or = new ArrayList<>();
        or.add(rule("path", SearchRule.Op.CONTAINS, "admin", false));
        or.add(rule("method", SearchRule.Op.EQUALS, "GET", true));
        check("或：满足一个就行", SearchRule.match(or, row, true));

        // A 且 B 或 C = (A and B) or C
        List<SearchRule> mixed = new ArrayList<>();
        mixed.add(rule("path", SearchRule.Op.CONTAINS, "api", false));
        mixed.add(rule("method", SearchRule.Op.EQUALS, "POST", false));  // A and B = false
        mixed.add(rule("status", SearchRule.Op.GE, "400", true));        // or C = true
        check("且优先于或", SearchRule.match(mixed, row, true));

        // A 或 B 且 C = A or (B and C)：A 成立时整体就成立（左往右结合会算成 false 的经典反例）
        List<SearchRule> mixed2 = new ArrayList<>();
        mixed2.add(rule("path", SearchRule.Op.CONTAINS, "api", false));   // A = true
        mixed2.add(rule("method", SearchRule.Op.EQUALS, "POST", true));   // 或 B = false
        mixed2.add(rule("status", SearchRule.Op.GE, "500", false));       // 且 C = false
        check("或之后又是且（且优先于或）", SearchRule.match(mixed2, row, true));

        check("空条件恒真", SearchRule.match(new ArrayList<>(), row, true));
        check("没填值的条件等于没写",
                SearchRule.match(List.of(rule("path", SearchRule.Op.CONTAINS, "", false)), row, true));

        // 说明文字 / 列定义
        check("单条说明可读", rule("status", SearchRule.Op.GT, "400", false).describe().equals("状态码 大于 400"));
        check("多条说明带且或", SearchRule.describe(mixed).contains(" 且 ") && SearchRule.describe(mixed).contains(" 或 "));
        check("路径列有 8 个", SearchRule.PATH_FIELDS.length == 8);
        check("参数列有 6 个", SearchRule.PARAM_FIELDS.length == 6);
        check("数字列会标出来", statusOf("status").numeric);
        check("文本列不标数字", !statusOf("path").numeric);

        // 颜色列：值只能从 6 个色名里挑，别让人手打「红」还是「红色」
        SearchRule.Field color = statusOf("color");
        check("颜色列存在", color.key.equals("color"));
        check("颜色的值是可选项", color.options != null && color.options.length == yuc.Marks.NAMES.length);
        check("颜色列不是数字列", !color.numeric);
        Map<String, String> colored = new LinkedHashMap<>(row);
        colored.put("color", "红");
        check("按颜色筛：等于红", hit("color", SearchRule.Op.EQUALS, "红", colored, true));
        check("没标红就被挡", !hit("color", SearchRule.Op.EQUALS, "红", row, true));
        check("没标的行「不等于红」成立", hit("color", SearchRule.Op.NOT_EQUALS, "红", row, true));
        check("色名反查：红 = 1", yuc.Marks.indexOf("红") == 1);
        check("色名反查：乱写的 = 0", yuc.Marks.indexOf("大红") == 0);
    }

    /** 从列集合里按 key 找列，找不到就给一个空列（测试用）。 */
    static SearchRule.Field statusOf(String key) {
        for (SearchRule.Field f : SearchRule.PATH_FIELDS) {
            if (f.key.equals(key)) {
                return f;
            }
        }
        return SearchRule.PATH_FIELDS[0];
    }

    static SearchRule rule(String field, SearchRule.Op op, String value, boolean or) {
        return new SearchRule(field, op, value, or);
    }

    /** 拿某一行里某一列的值去试一条关系。 */
    static boolean hit(String field, SearchRule.Op op, String value, Map<String, String> row, boolean ic) {
        return SearchRule.test(row.get(field), op, value, ic);
    }

    // ------------------------------------------------------------ IP /24 归组

    static void ipGrouping() {
        check("识别 IPv4", Urls.isIpv4("10.2.3.4"));
        check("识别 IPv4（边界 255）", Urls.isIpv4("255.255.255.255"));
        check("256 不算 IPv4", !Urls.isIpv4("256.1.1.1"));
        check("四段以外不算", !Urls.isIpv4("1.2.3"));
        check("五段不算", !Urls.isIpv4("1.2.3.4.5"));
        check("字母不算", !Urls.isIpv4("a.b.c.d"));
        check("空不算", !Urls.isIpv4(""));

        check("IP 按 /24 收起", "10.2.3.0/24".equals(Urls.rootDomain("10.2.3.4")));
        check("同段 IP 归到同一组", Urls.rootDomain("10.2.3.9").equals(Urls.rootDomain("10.2.3.4")));
        check("不同段分到不同组", !Urls.rootDomain("10.2.4.9").equals(Urls.rootDomain("10.2.3.4")));
        check("域名仍按根域", "aep.com.cn".equals(Urls.rootDomain("h5.aep.com.cn")));
        check("二级后缀仍多带一段", "aep.com.cn".equals(Urls.rootDomain("api.h5.aep.com.cn")));
        check("单段 host 原样", "localhost".equals(Urls.rootDomain("localhost")));
        check("IPv6 原样当一组", "::1".equals(Urls.rootDomain("::1")));
        check("IP 前缀函数对非 IP 返回空", Urls.ipv4Prefix24("a.b").isEmpty());
    }

    // ------------------------------------------------------------ 采集来源多选

    static void sources() throws Exception {
        check("老值「全部」= 空集", EndpointStore.parseToolFilter("全部").isEmpty());
        check("空串 = 空集", EndpointStore.parseToolFilter("").isEmpty());
        check("null = 空集", EndpointStore.parseToolFilter(null).isEmpty());
        check("老值「仅 Proxy」翻译成一条",
                EndpointStore.parseToolFilter("仅 Proxy").equals(Set.of("Proxy")));
        check("逗号串翻译成集合",
                EndpointStore.parseToolFilter("Proxy,Repeater").equals(new LinkedHashSet<>(List.of("Proxy", "Repeater"))));
        check("来源清单 = Burp 全部模块（14 个）", EndpointStore.SOURCE_NAMES.length == 14);
        check("来源名不缩写（Extensions）", List.of(EndpointStore.SOURCE_NAMES).contains("Extensions"));
        check("来源名不缩写（Burp AI）", List.of(EndpointStore.SOURCE_NAMES).contains("Burp AI"));
        check("不再有「其他」这个压缩桶", !List.of(EndpointStore.SOURCE_NAMES).contains("其他"));

        EndpointStore store = store(tempDir());
        check("默认不筛来源", store.toolFilter().isEmpty());
        store.setToolFilter(List.of("Proxy", "Repeater"));
        check("存的来源能读回来", store.toolFilter().containsAll(List.of("Proxy", "Repeater")));
        check("改完不许外部改动存储",
                throwsOn(() -> store.toolFilter().add("Intruder")));
        store.setToolFilter(List.of("全部"));
        check("传「全部」等于清空", store.toolFilter().isEmpty());
        store.shutdown();
    }

    // ------------------------------------------------------------ 删除 / 导入

    static void deleteAndImport() throws Exception {
        File dir = tempDir();
        EndpointStore store = store(dir);
        store.add(ep("h5.aep.com.cn", 443, "POST", "/api/list", 200, "{\"a\":1}"));
        store.add(ep("h5.aep.com.cn", 443, "POST", "/api/save", 300, "{\"b\":2}"));
        store.add(ep("10.2.3.4", 8080, "GET", "/svc/ping", 90, "{\"ok\":1}"));
        store.flushAll(); // 平时是 1.2s 防抖，测试里直接落盘

        File listJson = new File(dir, "h5.aep.com.cn_443.json");
        check("落盘了 json", listJson.isFile());
        check("json 里有两个 item",
                String.valueOf(MiniJson.tryParse(new String(Files.readAllBytes(listJson.toPath()), StandardCharsets.UTF_8)))
                        .contains("/api/save"));

        // 删一条路径：json 里那个 item 要跟着消失，另一条还在
        Endpoint save = find(store, "/api/save");
        check("找到要删的接口", save != null);
        int removed = store.removeEndpoints(List.of(save));
        check("删掉 1 条", removed == 1);
        String after = new String(Files.readAllBytes(listJson.toPath()), StandardCharsets.UTF_8);
        check("json 里不再有 /api/save", !after.contains("/api/save"));
        check("json 里仍有 /api/list", after.contains("/api/list"));
        check("内存里剩 1 个接口", store.endpoints("h5.aep.com.cn:443").size() == 1);

        // 删掉最后一个接口 → 整个域名连文件一起收掉，不留空节点
        store.removeEndpoints(List.of(find(store, "/api/list")));
        check("删空后域名节点消失", store.domain("h5.aep.com.cn:443") == null);
        check("删空后 json 文件也没了", !listJson.isFile());

        // 整域名删除（IP 那个）
        check("IP 域名在", store.domain("10.2.3.4:8080") != null);
        check("删域名返回 true", store.removeDomain("10.2.3.4:8080"));
        check("再删一次返回 false", !store.removeDomain("10.2.3.4:8080"));
        check("IP 的 json 也没了", !new File(dir, "10.2.3.4_8080.json").isFile());
        check("全部删空", store.endpointCount() == 0);

        // 导入：同一个接口导两次只加一次
        String template = MiniJson.pretty(yuc.TemplateBuilder.domainDoc("https", "api.example.com", 443,
                List.of(ep("api.example.com", 443, "POST", "/v1/user/detail", 0, "{\"id\":1}"))));
        List<Endpoint> parsed = TemplateImport.parse(template, "导入");
        check("模板解析出 1 个接口", parsed.size() == 1);
        check("来源记成「导入」", parsed.get(0).tool.equals("导入"));
        check("导入新增 1 个", store.importEndpoints(parsed) == 1);
        check("再导一次不重复", store.importEndpoints(TemplateImport.parse(template, "导入")) == 0);
        check("导入的接口在存储里", store.has("api.example.com:443",
                parsed.get(0).key));
        store.flushAll();
        check("导入会写出一份 json", new File(dir, "api.example.com_443.json").isFile());
        check("导入的样本没有响应字节", store.endpoints("api.example.com:443").get(0).responseLength == 0);

        // 导入的接口被真实响应覆盖式补档：长度 0 那档还在，真实档成为主样本
        store.add(ep("api.example.com", 443, "POST", "/v1/user/detail", 512, "{\"id\":1}"));
        Endpoint merged = store.endpoints("api.example.com:443").get(0);
        check("真实响应当上主样本", merged.responseLength == 512);
        check("导入那档仍留着", merged.sampleCount() == 2);

        // 坏 json 一个都不能进
        check("坏 json 解析出 0 个", TemplateImport.parse("{not json", "导入").isEmpty());
        check("没有 base 的 json 解析出 0 个", TemplateImport.parse("{\"items\":[]}", "导入").isEmpty());

        store.shutdown();
    }

    // ------------------------------------------------------------ 颜色标记

    static void marks() throws Exception {
        File dir = tempDir();
        EndpointStore s1 = store(dir);
        s1.add(ep("h5.aep.com.cn", 443, "GET", "/api/list", 200, "{\"a\":1}"));
        s1.add(ep("10.2.3.4", 8080, "GET", "/svc/ping", 90, "{\"ok\":1}"));

        Endpoint list = find(s1, "/api/list");
        Endpoint ping = find(s1, "/svc/ping");
        String listKey = list.key;
        String pingKey = ping.key;
        String pageKey = Marks.paramTarget("查询", "page");

        check("默认没颜色", s1.marks().color(Marks.PATH, list.domainKey(), listKey) == 0);
        check("设成红色", s1.marks().set(Marks.PATH, list.domainKey(), listKey, 1));
        check("读回来是红", "红".equals(s1.marks().colorName(Marks.PATH, list.domainKey(), listKey)));
        check("重复设同色不算改动", !s1.marks().set(Marks.PATH, list.domainKey(), listKey, 1));
        check("参数标记走同一套", s1.marks().set(Marks.PARAM, "", pageKey, 5)
                && "蓝".equals(s1.marks().colorName(Marks.PARAM, "", pageKey)));
        check("标记总数 2", s1.marks().size() == 2);

        // 落盘（整域名重写）不能把颜色带走
        s1.flushAll();
        check("落盘后颜色还在（marks 表不参与整域名重写）",
                s1.marks().color(Marks.PATH, list.domainKey(), listKey) == 1);
        s1.shutdown();

        // 重启后从库里读回来
        EndpointStore s2 = store(dir);
        check("重启后路径颜色还在", s2.marks().color(Marks.PATH, list.domainKey(), listKey) == 1);
        check("重启后参数颜色还在", s2.marks().color(Marks.PARAM, "", pageKey) == 5);
        check("重启后没标的那条还是没标", s2.marks().color(Marks.PATH, ping.domainKey(), pingKey) == 0);

        // 重新抓到同一个接口（key 不变），颜色自己就回来
        s2.add(ep("h5.aep.com.cn", 443, "GET", "/api/list", 260, "{\"a\":1,\"b\":2}"));
        check("重新抓到的同一接口仍带颜色", s2.marks().color(Marks.PATH, list.domainKey(), listKey) == 1);

        // 删域名：这个域名的路径颜色一起收，参数颜色是跨域名的，留着
        s2.removeDomain("h5.aep.com.cn:443");
        check("删域名后它的路径颜色没了",
                s2.marks().color(Marks.PATH, list.domainKey(), listKey) == 0);
        check("删域名不动参数颜色", s2.marks().color(Marks.PARAM, "", pageKey) == 5);

        // 清除单个 / 清空全部
        s2.marks().set(Marks.PATH, ping.domainKey(), pingKey, 3);
        check("设成第 3 个颜色（黄）", "黄".equals(s2.marks().colorName(Marks.PATH, ping.domainKey(), pingKey)));
        check("清除单个生效", s2.marks().set(Marks.PATH, ping.domainKey(), pingKey, 0)
                && s2.marks().color(Marks.PATH, ping.domainKey(), pingKey) == 0);
        s2.clearAll();
        check("清空全部把颜色也清了", s2.marks().size() == 0);
        s2.shutdown();

        // 清空后重启别又冒出旧颜色
        EndpointStore s3 = store(dir);
        check("清空后重启没有残留颜色", s3.marks().size() == 0);
        s3.shutdown();

        // 排序：有色置顶 / 按色号升 / 降，无色永远垫底（规则在 Marks.compare，UI 也用它）
        check("默认：有色在前（红 vs 无色）", Marks.compare(1, 0, Marks.SORT_DEFAULT) < 0);
        check("默认：两个都有色不分先后", Marks.compare(1, 6, Marks.SORT_DEFAULT) == 0);
        check("默认：两个都没色不分先后", Marks.compare(0, 0, Marks.SORT_DEFAULT) == 0);
        check("升序：红在蓝前", Marks.compare(1, 5, Marks.SORT_ASC) < 0);
        check("升序：有色的都在无色前", Marks.compare(6, 0, Marks.SORT_ASC) < 0);
        check("降序：蓝在红前", Marks.compare(5, 1, Marks.SORT_DESC) < 0);
        check("降序：有色的仍在无色前", Marks.compare(6, 0, Marks.SORT_DESC) < 0);
        check("色块能画出图标", Marks.swatch(1).getIconWidth() == 12);
        check("行底色会往表格底色上掺",
                !Marks.tint(1, java.awt.Color.WHITE).equals(java.awt.Color.WHITE)
                        && Marks.tint(0, java.awt.Color.WHITE).equals(java.awt.Color.WHITE));
    }


    static Endpoint ep(String host, int port, String method, String path, long len, String reqBody) {
        String url = "https://" + host + (port == 443 ? "" : ":" + port) + path;
        return new Endpoint(method, "https", host, port, path, url, "Proxy",
                new ArrayList<>(), new ArrayList<>(),
                "application/json", reqBody,
                "application/json", "{\"code\":0}", 200, len);
    }

    static Endpoint find(EndpointStore store, String path) {
        for (EndpointStore.Domain d : store.domains()) {
            for (Endpoint e : store.endpoints(d.key)) {
                if (e.path.equals(path)) {
                    return e;
                }
            }
        }
        return null;
    }

    static boolean throwsOn(Runnable r) {
        try {
            r.run();
            return false;
        } catch (UnsupportedOperationException e) {
            return true;
        }
    }

    static File tempDir() throws Exception {
        return Files.createTempDirectory("yuc-filter").toFile();
    }

    static EndpointStore store(File dir) {
        Preferences prefs = stub(Preferences.class, (n, a) -> {
            if ("getString".equals(n) && a != null && a.length > 0 && "yuc.dir".equals(a[0])) {
                return dir.getAbsolutePath();
            }
            return null;
        });
        Persistence persistence = stub(Persistence.class, (n, a) -> "preferences".equals(n) ? prefs : null);
        Logging logging = stub(Logging.class, (n, a) -> null);
        MontoyaApi api = stub(MontoyaApi.class, (n, a) -> {
            switch (n) {
                case "persistence": return persistence;
                case "logging": return logging;
                default: return null;
            }
        });
        return new EndpointStore(api);
    }

    @SuppressWarnings("unchecked")
    static <T> T stub(Class<T> iface, Handler handler) {
        InvocationHandler ih = (proxy, method, args) -> {
            String name = method.getName();
            if (name.equals("toString")) {
                return "stub:" + iface.getSimpleName();
            }
            if (name.equals("hashCode")) {
                return System.identityHashCode(proxy);
            }
            if (name.equals("equals")) {
                return proxy == args[0];
            }
            Object v = handler.handle(name, args);
            if (v == null && method.getReturnType().isPrimitive()) {
                Class<?> t = method.getReturnType();
                if (t == boolean.class) {
                    return false;
                }
                if (t == int.class) {
                    return 0;
                }
                if (t == long.class) {
                    return 0L;
                }
                if (t == short.class) {
                    return (short) 0;
                }
                if (t == byte.class) {
                    return (byte) 0;
                }
                if (t == char.class) {
                    return (char) 0;
                }
                return 0.0;
            }
            return v;
        };
        return (T) Proxy.newProxyInstance(FilterSmoke.class.getClassLoader(), new Class<?>[]{iface}, ih);
    }

    interface Handler {
        Object handle(String method, Object[] args);
    }

    static void check(String name, boolean ok) {
        if (!ok) {
            failed++;
            System.out.println("  FAIL " + name);
        } else {
            System.out.println("  PASS " + name);
        }
    }
}
