import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.persistence.Persistence;
import burp.api.montoya.persistence.Preferences;
import burp.api.montoya.proxy.Proxy;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import yuc.Endpoint;
import yuc.EndpointStore;
import yuc.HistoryImport;

import java.lang.reflect.InvocationHandler;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 「导入历史」冒烟测试：伪造一份 Proxy history，验证规则与实时采集一致、
 * 采集开关关闭时照样能补捞、同接口仍然只留最长响应。
 */
public class HistorySmoke {

    static int failed = 0;

    public static void main(String[] args) throws Exception {
        // 存储目录钉在临时目录：构造 EndpointStore 时会读 yuc.dir，指错地方会动到真实数据
        EndpointStore store = new EndpointStore(apiFor(Files.createTempDirectory("yuc-hist").toFile()));
        // 关键：采集开关是关的，导入必须照样生效
        store.setRecording(false);

        List<ProxyHttpRequestResponse> history = new ArrayList<>();
        history.add(item("GET", "https://h5.aep.com.cn/api/v1/list?page=1",
                null, "", "application/json", "{\"a\":1}", 200, true));
        history.add(item("GET", "https://h5.aep.com.cn/api/v1/list?page=2",
                null, "", "application/json", "{\"a\":1,\"b\":2}", 200, true));
        history.add(item("GET", "https://h5.aep.com.cn/static/app.js?v=1",
                null, "", "application/json", "{\"a\":1}", 200, true));
        history.add(item("GET", "https://h5.aep.com.cn/api/html",
                null, "", "text/html", "<html>hi</html>", 200, true));
        history.add(item("GET", "https://h5.aep.com.cn/api/none",
                null, "", "application/json", "", 0, false));
        history.add(item("PROPFIND", "https://h5.aep.com.cn/api/prop",
                null, "", "application/json", "{\"a\":1}", 200, true));
        history.add(item("POST", "https://api.example.com/v1/save",
                "application/json", "{\"x\":1}", "application/json", "{\"ok\":true}", 200, true));
        history.add(item("GET", "https://h5.aep.com.cn/api/fake",
                null, "", "application/json", "<html>oops</html>", 200, true));
        // HTML 页面：默认类型里没有 HTML，所以这一条应该被类型挡掉
        history.add(item("GET", "https://h5.aep.com.cn/page.html",
                null, "", "text/html", "<html><body>page</body></html>", 200, true));
        // 同一接口第二次、请求体多了一个字段：参数形状变了 → 该留一档，且更长的当主样本
        history.add(item("POST", "https://api.example.com/v2/save",
                "application/json", "{\"x\":1}", "application/json", "{\"ok\":1}", 200, true));
        history.add(item("POST", "https://api.example.com/v2/save",
                "application/json", "{\"x\":1,\"y\":2}", "application/json", "{\"ok\":1,\"extra\":true}", 200, true));

        Proxy proxy = stub(Proxy.class, (n, a) -> "history".equals(n) ? history : null);
        MontoyaApi api = stub(MontoyaApi.class, (n, a) -> "proxy".equals(n) ? proxy : null);

        HistoryImport.Result r = HistoryImport.run(api, store, null);

        check("扫描条数 = 历史长度", r.scanned == 11);
        check("通过规则 5 条", r.kept == 5);
        check("新增 3 个接口", r.added == 3);
        check("替换 1 条（新形状 + 响应更长）", r.updated == 1);
        check("有 1 条同参数被跳过", r.unchanged == 1);
        check("其余 6 条被规则挡掉（含 HTML 页面）", r.dropped == 6);
        check("没有异常条目", r.failed == 0);
        check("采集开关关闭也能补捞", store.endpointCount() == 3);

        check("静态资源被挡", !hasPath(store, "/static/app.js"));
        check("HTTP 响应被挡", !hasPath(store, "/api/html"));
        check("非标准方法被挡", !hasPath(store, "/api/prop"));
        check("头写 json 实际 HTML 被挡", !hasPath(store, "/api/fake"));
        check("多域名都收下", store.domains().size() == 2);

        Endpoint list = find(store, "/api/v1/list");
        // page=1 与 page=2 参数名一样，算同一种请求形状：第二条不占新档
        check("同参数形状只留一档", list != null && list.sampleCount() == 1);
        check("留下的是先抓到的那条", list != null && list.responseBody.contains("\"a\":1")
                && !list.responseBody.contains("\"b\""));
        check("来源标成 Proxy", list != null && "Proxy".equals(list.tool));
        check("query 参数仍在", list != null && list.query.size() == 1);

        Endpoint v2 = find(store, "/v2/save");
        check("参数变了就是新档", v2 != null && v2.sampleCount() == 2);
        check("更长的那个当主样本", v2 != null && v2.responseBody.contains("extra"));
        check("旧档仍能还原请求", v2 != null && v2.samples().get(0).requestBody.equals("{\"x\":1}"));

        Endpoint save = find(store, "/v1/save");
        check("请求体被记下", save != null && save.requestBody.contains("\"x\""));
        check("请求头被记下", save != null && save.requestHeaders.size() > 0);

        check("结果摘要包含扫描数", r.summary().contains("扫描 11 条"));
        check("结果摘要不含 null", !r.summary().contains("null"));

        store.flushAll();
        java.io.File f = new java.io.File(store.dir(), "h5.aep.com.cn_443.json");
        check("落盘 域名_端口.json", f.exists());
        String json = f.exists() ? Files.readString(f.toPath(), StandardCharsets.UTF_8) : "";
        check("落盘内容含接口路径", json.contains("/api/v1/list"));

        // 再来一次：通过规则数不变，但一条都不会被写进去
        HistoryImport.Result again = HistoryImport.run(api, store, null);
        check("重复导入不新增", again.added == 0);
        check("重复导入通过规则数不变", again.kept == 5);
        check("重复导入全部计入未变动", again.unchanged == 5);
        check("重复导入不替换", again.updated == 0);

        // 打开 HTML 类型后再补捞一次：只有那条页面进来，其余仍然全部已留档
        store.setRecordTypes(java.util.List.of("JSON", "HTML"));
        HistoryImport.Result pages = HistoryImport.run(api, store, null);
        // /page.html 和 /api/html 都是 text/html，开了类型就一起进来
        check("开 HTML 后补捞到 2 个页面", pages.added == 2);
        check("页面在存储里", find(store, "/page.html") != null);
        check("页面正文也进来了（导入历史不解析字段，但正文留着）",
                find(store, "/page.html") != null && find(store, "/page.html").responseBody.contains("page"));
        check("其余 5 条仍然算已留档", pages.unchanged == 5 && pages.updated == 0);
        check("规则挡掉的从 6 条降到 4 条", pages.dropped == 4);

        // history() 抛异常时不能把界面搞崩
        MontoyaApi broken = stub(MontoyaApi.class, (n, a) -> {
            if ("proxy".equals(n)) {
                throw new IllegalStateException("burp 没就绪");
            }
            return null;
        });
        HistoryImport.Result bad = HistoryImport.run(broken, store, null);
        check("读不到 history 时返回错误而不是抛异常", bad.error != null);
        check("错误摘要可读", bad.summary().startsWith("读取 Proxy 历史失败"));

        System.out.println(failed == 0 ? "HISTORY PASS" : "HISTORY FAILED: " + failed);
        if (failed > 0) {
            System.exit(1);
        }
    }

    /** 只提供 persistence 的假 api：把存储目录钉在临时目录。 */
    static MontoyaApi apiFor(java.io.File dir) {
        Preferences prefs = stub(Preferences.class, (n, a) -> "getString".equals(n)
                && a != null && a.length > 0 && "yuc.dir".equals(a[0]) ? dir.getAbsolutePath() : null);
        Persistence p = stub(Persistence.class, (n, a) -> "preferences".equals(n) ? prefs : null);
        return stub(MontoyaApi.class, (n, a) -> "persistence".equals(n) ? p : null);
    }

    static boolean hasPath(EndpointStore store, String path) {
        return find(store, path) != null;
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

    static ProxyHttpRequestResponse item(String method, String url, String reqCt, String reqBody,
                                         String respCt, String respBody, int status, boolean hasResponse) {
        HttpService service = stub(HttpService.class, (n, a) -> {
            switch (n) {
                case "secure": return url.startsWith("https");
                case "host": return hostOf(url);
                case "port": return url.startsWith("https") ? 443 : 80;
                default: return null;
            }
        });
        Map<String, String> reqHeaders = new HashMap<>();
        if (reqCt != null) {
            reqHeaders.put("content-type", reqCt);
        }
        reqHeaders.put("cookie", "sid=abc");
        HttpRequest request = stub(HttpRequest.class, (n, a) -> {
            switch (n) {
                case "method": return method;
                case "url": return url;
                case "httpService": return service;
                case "body": return bytes(reqBody);
                case "bodyToString": return reqBody;
                case "headers": return headerList(reqHeaders);
                case "headerValue": return reqHeaders.get(String.valueOf(a[0]).toLowerCase());
                default: return null;
            }
        });
        Map<String, String> respHeaders = new HashMap<>();
        if (respCt != null) {
            respHeaders.put("content-type", respCt);
        }
        HttpResponse response = stub(HttpResponse.class, (n, a) -> {
            switch (n) {
                case "body": return bytes(respBody);
                case "bodyToString": return respBody;
                case "statusCode": return (short) status;
                case "headerValue": return respHeaders.get(String.valueOf(a[0]).toLowerCase());
                default: return null;
            }
        });
        return stub(ProxyHttpRequestResponse.class, (n, a) -> {
            switch (n) {
                case "hasResponse": return hasResponse;
                case "request":
                case "finalRequest": return request;
                case "response":
                case "originalResponse": return response;
                case "httpService": return service;
                case "url": return url;
                case "method": return method;
                case "id": return 1;
                default: return null;
            }
        });
    }

    static List<HttpHeader> headerList(Map<String, String> raw) {
        List<HttpHeader> out = new ArrayList<>();
        for (Map.Entry<String, String> e : raw.entrySet()) {
            out.add(stub(HttpHeader.class, (n, a) -> {
                switch (n) {
                    case "name": return e.getKey();
                    case "value": return e.getValue();
                    case "toString": return e.getKey() + ": " + e.getValue();
                    default: return null;
                }
            }));
        }
        return out;
    }

    static String hostOf(String url) {
        String s = url.substring(url.indexOf("://") + 3);
        int slash = s.indexOf('/');
        String authority = slash < 0 ? s : s.substring(0, slash);
        int colon = authority.indexOf(':');
        return colon < 0 ? authority : authority.substring(0, colon);
    }

    static ByteArray bytes(String s) {
        byte[] raw = s == null ? new byte[0] : s.getBytes(StandardCharsets.UTF_8);
        return stub(ByteArray.class, (n, a) -> {
            switch (n) {
                case "getBytes": return raw;
                case "length": return raw.length;
                case "toString": return s;
                default: return null;
            }
        });
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
        return (T) java.lang.reflect.Proxy.newProxyInstance(HistorySmoke.class.getClassLoader(),
                new Class<?>[]{iface}, ih);
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
