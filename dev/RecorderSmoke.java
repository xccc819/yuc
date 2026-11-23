import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.ToolSource;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.persistence.Persistence;
import burp.api.montoya.persistence.Preferences;
import yuc.Endpoint;
import yuc.EndpointStore;
import yuc.Recorder;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 采集规则冒烟测试：直接喂「假的响应对象」给 Recorder，验证哪些该收、哪些该丢。
 * 这样不用起 Burp 就能把过滤逻辑跑一遍。
 */
public class RecorderSmoke {

    static int failed = 0;

    public static void main(String[] args) throws Exception {
        // 注意：必须把「存储目录」指到临时目录，否则 EndpointStore 构造时会
        // 去读真实的 ~/yuc-output（会触发老数据迁移，污染用户数据）
        EndpointStore store = new EndpointStore(apiFor(Files.createTempDirectory("yuc-rec").toFile()));
        store.setRecording(true);
        Recorder recorder = new Recorder(null, store);

        fire(recorder, resp("GET", "https://h5.demo.com.cn/api/v1/list?page=1",
                "application/json", "{\"a\":1}", "application/json; charset=utf-8",
                "{\"code\":0,\"data\":{\"list\":[{\"id\":1,\"name\":\"x\"}]}}", 200));
        fire(recorder, resp("GET", "https://h5.demo.com.cn/api/v1/list?page=2",
                "application/json", "{\"a\":1}", "application/json",
                "{\"code\":0,\"data\":{\"list\":[{\"id\":2}]}}", 200));
        check("同接口第二次（响应更短）不新增", store.endpoints("h5.demo.com.cn:443").size() == 1);
        check("保留的是更长的那次", store.endpoints("h5.demo.com.cn:443").get(0).path.equals("/api/v1/list"));

        fire(recorder, resp("GET", "https://h5.demo.com.cn/static/app.js?v=1",
                null, "", "application/json", "{\"a\":1}", 200));
        check("末段含点号 → 跳过", store.endpoints("h5.demo.com.cn:443").size() == 1);

        fire(recorder, resp("GET", "https://h5.demo.com.cn/v1/user.json",
                null, "", "application/json", "{\"a\":1}", 200));
        check(".json 后缀 → 跳过", store.endpoints("h5.demo.com.cn:443").size() == 1);

        fire(recorder, resp("GET", "https://h5.demo.com.cn/api/x#frag",
                null, "", "application/json", "{\"a\":1}", 200));
        check("带 # → 跳过", store.endpoints("h5.demo.com.cn:443").size() == 1);

        fire(recorder, resp("GET", "https://h5.demo.com.cn/api/html",
                null, "", "text/html", "<html><body>hi</body></html>", 200));
        check("text/html 响应 → 跳过", store.endpoints("h5.demo.com.cn:443").size() == 1);

        fire(recorder, resp("GET", "https://h5.demo.com.cn/api/fake",
                null, "", "application/json", "<html>oops</html>", 200));
        check("头是 json 但内容是 HTML → 跳过", store.endpoints("h5.demo.com.cn:443").size() == 1);

        fire(recorder, resp("PROPFIND", "https://h5.demo.com.cn/api/prop",
                null, "", "application/json", "{\"a\":1}", 200));
        check("非标准方法 → 跳过", store.endpoints("h5.demo.com.cn:443").size() == 1);

        fire(recorder, resp("GET", "https://h5.demo.com.cn/api/empty",
                null, "", "application/json", "", 204));
        check("空响应体 → 跳过", store.endpoints("h5.demo.com.cn:443").size() == 1);

        fire(recorder, resp("POST", "https://h5.demo.com.cn/api/save",
                "application/json", "{\"name\":\"张三\",\"n\":1}", "application/json",
                "{\"code\":0}", 200));
        check("正常 JSON 接口 → 收录", store.endpoints("h5.demo.com.cn:443").size() == 2);

        Endpoint saved = null;
        for (Endpoint e : store.endpoints("h5.demo.com.cn:443")) {
            if (e.path.equals("/api/save")) {
                saved = e;
            }
        }
        check("请求体被记录", saved != null && saved.requestBody.contains("张三"));
        check("工具来源被记录", saved != null && "Proxy".equals(saved.tool));
        String raw = saved == null ? "" : new String(saved.rawRequestBytes(), StandardCharsets.UTF_8);
        check("能拼回请求行", raw.startsWith("POST /api/save HTTP/1.1\r\n"));
        check("能拼回原始头", raw.contains("content-type: application/json"));
        check("补上 Host", raw.contains("Host: h5.demo.com.cn"));
        check("body 原样保留", raw.endsWith("{\"name\":\"张三\",\"n\":1}"));

        store.flushAll();
        String json = Files.readString(new java.io.File(store.dir(), "h5.demo.com.cn_443.json").toPath(),
                StandardCharsets.UTF_8);
        check("落盘文件名 域名_端口.json", json.contains("\"host\": \"h5.demo.com.cn\""));
        System.out.println("[recorder]\n" + json);

        // ---------------------------------------- 记录类型：默认只 JSON，HTML 手动开
        check("默认只记 JSON", store.recordTypes().equals(java.util.Set.of("JSON")));
        check("上面那条 text/html 被挡，就是因为类型没开", find(store, "/api/html") == null);

        store.setRecordTypes(List.of("JSON", "HTML"));
        check("勾上 HTML 后两种都在", store.recordTypes().contains("HTML")
                && store.recordTypes().contains("JSON"));
        int htmlBefore = store.endpointCount();

        fire(recorder, resp("GET", "https://h5.demo.com.cn/login.html",
                null, "", "text/html; charset=utf-8", "<html><body>登录</body></html>", 200));
        check("开了 HTML 之后 .html 页面收下", store.endpointCount() == htmlBefore + 1);

        Endpoint page = find(store, "/login.html");
        check("「末段含点号」不再挡 HTML（这条只对 JSON 生效）", page != null);
        check("HTML 正文存下来了（详情窗口能看到）", page != null && page.responseBody.contains("登录"));
        check("HTML 页面没有 JSON 字段，参数 0 个", page != null && page.paramCount() == 0);
        check("HTML 页面的响应类型原样记着",
                page != null && page.responseContentType != null
                        && page.responseContentType.contains("text/html"));

        fire(recorder, resp("GET", "https://h5.demo.com.cn/login.html",
                null, "", "text/html", "<html><body>登录</body></html>", 200));
        check("HTML 也走同一套去重（同长度不新增）", store.endpointCount() == htmlBefore + 1);

        fire(recorder, resp("GET", "https://h5.demo.com.cn/logo.png",
                null, "", "image/png", "PNG-bytes", 200));
        check("图片仍然不进（类型不认，跟开关无关）", store.endpointCount() == htmlBefore + 1);

        fire(recorder, resp("GET", "https://h5.demo.com.cn/api/after-html",
                null, "", "application/json", "{\"ok\":1}", 200));
        check("开了 HTML 也不影响 JSON 照收", store.endpointCount() == htmlBefore + 2);

        // 边界：全不勾 → 退回只 JSON，绝不出现「一条都不记」
        store.setRecordTypes(new ArrayList<>());
        check("全不勾退回「只 JSON」", store.recordTypes().equals(java.util.Set.of("JSON")));
        store.setRecordTypes(List.of("json", "html", "xml"));
        check("小写也认、认不出的类型名直接忽略",
                store.recordTypes().equals(new java.util.LinkedHashSet<>(List.of("JSON", "HTML"))));
        check("老配置（空串）按只 JSON 解析",
                EndpointStore.parseRecordTypes("").equals(java.util.Set.of("JSON")));
        check("只勾 HTML 也留得住",
                EndpointStore.parseRecordTypes("HTML").equals(java.util.Set.of("HTML")));

        // 关掉采集开关后一条都不收
        store.setRecording(false);
        int before = store.endpointCount();
        fire(recorder, resp("GET", "https://h5.demo.com.cn/api/other",
                null, "", "application/json", "{\"a\":1}", 200));
        check("未勾选采集 → 不记录", store.endpointCount() == before);

        System.out.println(failed == 0 ? "RECORDER PASS" : "RECORDER FAILED: " + failed);
        if (failed > 0) {
            System.exit(1);
        }
    }

    /** 按路径找样本（主样本那批）。 */
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

    /** 只提供 persistence 的假 api：把存储目录钉在临时目录，别碰真实的 ~/yuc-output。 */
    static MontoyaApi apiFor(java.io.File dir) {
        Preferences prefs = stub(Preferences.class, (n, a) -> "getString".equals(n)
                && a != null && a.length > 0 && "yuc.dir".equals(a[0]) ? dir.getAbsolutePath() : null);
        Persistence p = stub(Persistence.class, (n, a) -> "preferences".equals(n) ? prefs : null);
        return stub(MontoyaApi.class, (n, a) -> "persistence".equals(n) ? p : null);
    }

    /** Burp 的 ResponseReceivedAction 需要 ObjectFactory，离线环境没有，吞掉即可（capture 已经跑完）。 */
    static void fire(Recorder recorder, HttpResponseReceived resp) {
        try {
            recorder.handleHttpResponseReceived(resp);
        } catch (NullPointerException expectedOffline) {
            // 只有 return 语句里的工厂调用会炸
        }
    }

    static HttpResponseReceived resp(String method, String url, String reqCt, String reqBody,
                                     String respCt, String respBody, int status) {
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
        ToolSource source = stub(ToolSource.class, (n, a) -> "toolType".equals(n) ? ToolType.PROXY : null);
        Map<String, String> respHeaders = new HashMap<>();
        if (respCt != null) {
            respHeaders.put("content-type", respCt);
        }
        return stub(HttpResponseReceived.class, (n, a) -> {
            switch (n) {
                case "initiatingRequest": return request;
                case "toolSource": return source;
                case "body": return bytes(respBody);
                case "bodyToString": return respBody;
                case "statusCode": return (short) status;
                case "headerValue": return respHeaders.get(String.valueOf(a[0]).toLowerCase());
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
        return (T) Proxy.newProxyInstance(RecorderSmoke.class.getClassLoader(), new Class<?>[]{iface}, ih);
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
