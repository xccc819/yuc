import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.persistence.Persistence;
import burp.api.montoya.persistence.Preferences;
import yuc.Endpoint;
import yuc.EndpointStore;
import yuc.HeaderPolicy;
import yuc.MiniJson;
import yuc.Params;
import yuc.TemplateBuilder;
import yuc.TemplateImport;

import java.io.File;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * base.headers 全链路自测：判定规则 → 投票挑值 → 模板只写一次 → 参数表「请求头」来源
 * → SQLite 往返 → 老 json 读回。
 */
public class BaseHeaderSmoke {

    static int failed = 0;

    /** 长到会被界面截断的 Cookie 值。 */
    static final String LONG_COOKIE = "SID=" + "a".repeat(200) + "; lang=zh";

    public static void main(String[] args) throws Exception {
        policy();
        voting();
        template();
        paramSource();
        dbRoundTrip();
        legacyImport();

        System.out.println(failed == 0 ? "BASEHEADER PASS" : "BASEHEADER FAILED: " + failed);
        if (failed > 0) {
            System.exit(1);
        }
    }

    // ------------------------------------------------------------ 判定规则
    static void policy() {
        check("Cookie 进 base", HeaderPolicy.isSharedHeader("Cookie"));
        check("Authorization 进 base", HeaderPolicy.isSharedHeader("Authorization"));
        check("X-Api-Key 进 base", HeaderPolicy.isSharedHeader("X-Api-Key"));
        check("X-CSRF-Token 进 base", HeaderPolicy.isSharedHeader("X-CSRF-Token"));
        check("X-Session-Id 进 base", HeaderPolicy.isSharedHeader("X-Session-Id"));
        check("大小写不敏感", HeaderPolicy.isSharedHeader("AUTHORIZATION"));

        check("Cache-Control 不进 base", !HeaderPolicy.isSharedHeader("Cache-Control"));
        check("If-None-Match 不进 base", !HeaderPolicy.isSharedHeader("If-None-Match"));
        check("If-Modified-Since 不进 base", !HeaderPolicy.isSharedHeader("If-Modified-Since"));
        check("ETag 不进 base", !HeaderPolicy.isSharedHeader("ETag"));
        check("Pragma 不进 base", !HeaderPolicy.isSharedHeader("Pragma"));
        check("Expires 不进 base", !HeaderPolicy.isSharedHeader("Expires"));
        check("X-Cache 不进 base", !HeaderPolicy.isSharedHeader("X-Cache-Lookup"));

        check("Accept 不进 base", !HeaderPolicy.isSharedHeader("Accept-Language"));
        check("User-Agent 不进 base", !HeaderPolicy.isSharedHeader("User-Agent"));
        check("Sec-Fetch 不进 base", !HeaderPolicy.isSharedHeader("Sec-Fetch-Site"));
        check("Host / Content-Length / Content-Type 不进 base",
                !HeaderPolicy.isSharedHeader("Host")
                        && !HeaderPolicy.isSharedHeader("Content-Length")
                        && !HeaderPolicy.isSharedHeader("Content-Type"));
        check("普通业务头不进 base（不是鉴权信息）",
                !HeaderPolicy.isSharedHeader("X-Request-Id"));

        check("isCacheHeader 认 x-cache", HeaderPolicy.isCacheHeader("X-Cache"));
        check("isCacheHeader 认 if-none-match", HeaderPolicy.isCacheHeader("If-None-Match"));
        check("isCacheHeader 不误伤 Authorization", !HeaderPolicy.isCacheHeader("Authorization"));
    }

    // -------------------------------------------------------------- 投票挑值
    static void voting() {
        List<Endpoint> eps = new ArrayList<>();
        eps.add(ep("/a", "SID=aaa; lang=zh", "Bearer t0"));
        eps.add(ep("/b", "SID=aaa; lang=zh", "Bearer t0"));
        eps.add(ep("/c", "SID=bbb; lang=zh", "Bearer t0"));
        Map<String, String> base = HeaderPolicy.collect(eps);
        check("挑出 Cookie", base.containsKey("Cookie"));
        check("取出现次数最多的值（2:1 → aaa）", "SID=aaa; lang=zh".equals(base.get("Cookie")));
        check("Authorization 只留一个值", "Bearer t0".equals(base.get("Authorization")));
        check("缓存头混进来也会被滤掉（UA/Cache 不进 collect）",
                !base.containsKey("User-Agent") && !base.containsKey("Cache-Control"));

        // 同票取后出现的
        List<Endpoint> tie = new ArrayList<>();
        tie.add(ep("/x", "SID=first", ""));
        tie.add(ep("/y", "SID=second", ""));
        check("同票取后出现的那个值", "SID=second".equals(HeaderPolicy.collect(tie).get("Cookie")));

        check("空列表 → 空 map", HeaderPolicy.collect(List.of()).isEmpty());
        check("asPairs 排掉缓存类",
                HeaderPolicy.asPairs(Map.of("Cookie", "a=1", "Cache-Control", "no-cache")).size() == 1);
    }

    // -------------------------------------------------- 模板里只写一次
    static void template() {
        List<Endpoint> eps = new ArrayList<>();
        eps.add(ep("/a", "SID=aaa; lang=zh", "Bearer t0"));
        eps.add(ep("/b", "SID=aaa; lang=zh", "Bearer t0"));
        // 第三个接口用的是另一套会话：不该被 base 吞掉
        eps.add(ep("/c", "OTHER=zzz", "Bearer t0"));

        Map<String, Object> doc = TemplateBuilder.domainDoc("https", "h5.aep.com.cn", 443, eps);
        String json = MiniJson.pretty(doc);

        check("base 里有 headers", json.contains("\"headers\""));
        check("Cookie 写进 base", json.contains("\"Cookie\""));
        check("Authorization 写进 base", json.contains("\"Authorization\""));

        int cookieHits = count(json, "SID=aaa");
        check("共用的 Cookie 在模板里只出现 1 次（不是 3 次）", cookieHits == 1);
        check("另一套会话的 Cookie 仍留在 item 里", json.contains("\"OTHER\"") && json.contains("\"zzz\""));
        check("接口自己的 cookie 行还在（不匹配 base 就不删）", json.contains("\"cookie\""));
        check("Accept/UA 这类没写进 base", !json.contains("\"User-Agent\""));
    }

    // ------------------------------------------------ 参数表「请求头」来源
    static void paramSource() {
        List<Endpoint> eps = new ArrayList<>();
        eps.add(ep("/a", LONG_COOKIE, "Bearer t0"));
        eps.add(ep("/b", LONG_COOKIE, "Bearer t0"));

        Map<String, String> base = HeaderPolicy.collect(eps);
        List<Params.ParamStat> stats = Params.stats(eps, base);

        Params.ParamStat cookie = null;
        Params.ParamStat auth = null;
        boolean anyHeaderSource = false;
        boolean cacheLeak = false;
        for (Params.ParamStat st : stats) {
            if ("请求头".equals(st.where)) {
                anyHeaderSource = true;
                cacheLeak |= HeaderPolicy.isCacheHeader(st.name);
                if ("Cookie".equals(st.name)) {
                    cookie = st;
                }
                if ("Authorization".equals(st.name)) {
                    auth = st;
                }
            }
        }
        check("参数表出现「请求头」来源", anyHeaderSource);
        check("请求头里不含缓存键", !cacheLeak);
        check("Cookie 作为参数出现", cookie != null);
        check("base 头对所有接口生效（接口数 = 总数 2）", cookie != null && cookie.endpoints == 2);
        check("Authorization 也在", auth != null);
        check("展示值被截断", cookie != null && cookie.example.endsWith("…"));
        check("payload 用完整值（不是截断的）", cookie != null && cookie.payload.equals(LONG_COOKIE));

        // 不传 base 时不该冒出请求头行
        boolean leak = false;
        for (Params.ParamStat st : Params.stats(eps)) {
            leak |= "请求头".equals(st.where);
        }
        check("不传 baseHeaders 就不显示请求头来源", !leak);

        // JSON 里的长字符串：展示截断，payload 完整
        String longValue = "x".repeat(200);
        String body = "{\"note\":\"" + longValue + "\"}";
        Endpoint json = new Endpoint("POST", "https", "h5.aep.com.cn", 443, "/api/save",
                "https://h5.aep.com.cn/api/save", "Proxy",
                new ArrayList<>(), new ArrayList<>(), new ArrayList<>(),
                body.getBytes(StandardCharsets.UTF_8), "application/json", body,
                "application/json", "{\"ok\":true}", 200, 20);
        Params.ParamStat note = null;
        for (Params.ParamStat st : Params.stats(List.of(json))) {
            if ("请求体".equals(st.where) && "note".equals(st.name)) {
                note = st;
            }
        }
        check("JSON 参数能统计到", note != null);
        check("JSON 长值展示被截断", note != null && note.example.endsWith("…"));
        check("JSON 长值 payload 完整", note != null && note.payload.equals(longValue));
    }

    // ------------------------------------------------------ SQLite 往返
    static void dbRoundTrip() throws Exception {
        File dir = Files.createTempDirectory("yuc-base").toFile();
        EndpointStore s1 = store(dir);
        s1.add(ep("/a", "SID=aaa", "Bearer t0"));
        s1.add(ep("/b", "SID=aaa", "Bearer t0"));
        s1.flushAll();
        s1.shutdown();

        EndpointStore s2 = store(dir);
        Endpoint a = find(s2, "/a");
        check("重启后接口还在", a != null);
        check("重启后 base 头从 domain_headers 回来了", a != null && hasHeader(a, "Cookie"));
        check("重启后 Authorization 也回来了", a != null && hasHeader(a, "Authorization"));
        check("重启后缓存头没跟着回来", a != null && !hasHeader(a, "Cache-Control"));
        check("重启后 UA 没被当成 base 头", a != null && !hasHeader(a, "User-Agent"));
        check("重启后 Cookie 值完整", a != null && "SID=aaa".equals(headerValue(a, "Cookie")));

        // 重启后导出的模板仍带 base.headers
        String json = MiniJson.pretty(TemplateBuilder.domainDoc("https", "h5.aep.com.cn", 443,
                s2.endpoints("h5.aep.com.cn:443")));
        check("重启后导出的模板仍带 base.headers", json.contains("\"Cookie\""));
        s2.shutdown();

        // 清空域名时头也要清掉
        EndpointStore s3 = store(dir);
        s3.clearAll();
        s3.shutdown();
        EndpointStore s4 = store(dir);
        check("清空后没有残留的头", s4.endpointCount() == 0);
        s4.shutdown();
    }

    // -------------------------------------------- 老 json 的 base.headers
    static void legacyImport() {
        List<Endpoint> eps = TemplateImport.parse("{\n"
                + "  \"base\": {\"scheme\": \"https\", \"host\": \"md.cnnc.cn\", \"port\": 443,\n"
                + "    \"headers\": {\"Cookie\": \"SID=old\", \"Cache-Control\": \"no-cache\"}},\n"
                + "  \"items\": [{\"id\": \"a\", \"name\": \"GET /x\", \"method\": \"GET\", \"uri\": \"/x\"}]\n"
                + "}");
        check("老 json 能解析出 1 条", eps.size() == 1);
        Endpoint e = eps.isEmpty() ? null : eps.get(0);
        check("base.headers 注回样本", e != null && "SID=old".equals(headerValue(e, "Cookie")));
        check("缓存头被丢掉（不影响参数统计）", e != null && !hasHeader(e, "Cache-Control"));
        check("导入的样本没有 cookie 参数行重复",
                e != null && Params.templateParams(e).stream()
                        .noneMatch(r -> "cookie".equals(String.valueOf(r.get("in")))));
    }

    // ---------------------------------------------------------------- 工具

    /** 造一条带鉴权头 + 一个缓存头的端点。 */
    static Endpoint ep(String path, String cookie, String auth) {
        List<String[]> headers = new ArrayList<>();
        headers.add(new String[]{"Host", "h5.aep.com.cn"});
        if (!cookie.isEmpty()) {
            headers.add(new String[]{"Cookie", cookie});
        }
        if (!auth.isEmpty()) {
            headers.add(new String[]{"Authorization", auth});
        }
        headers.add(new String[]{"Cache-Control", "no-cache"});
        headers.add(new String[]{"User-Agent", "Mozilla/5.0"});
        headers.add(new String[]{"Accept", "application/json"});

        List<String[]> cookies = new ArrayList<>();
        for (String[] c : yuc.Urls.cookiePairs(cookie)) {
            cookies.add(c);
        }
        return new Endpoint("GET", "https", "h5.aep.com.cn", 443, path,
                "https://h5.aep.com.cn" + path, "Proxy",
                new ArrayList<>(), cookies, headers, new byte[0],
                "", "", "application/json", "{\"code\":0}", 200, 20);
    }

    static boolean hasHeader(Endpoint ep, String name) {
        return headerValue(ep, name) != null;
    }

    static String headerValue(Endpoint ep, String name) {
        for (String[] h : ep.requestHeaders) {
            if (h[0].equalsIgnoreCase(name)) {
                return h[1];
            }
        }
        return null;
    }

    static int count(String haystack, String needle) {
        int n = 0;
        int i = haystack.indexOf(needle);
        while (i >= 0) {
            n++;
            i = haystack.indexOf(needle, i + needle.length());
        }
        return n;
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
        return (T) Proxy.newProxyInstance(BaseHeaderSmoke.class.getClassLoader(), new Class<?>[]{iface}, ih);
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
