import burp.api.montoya.MontoyaApi;
import burp.api.montoya.persistence.Persistence;
import burp.api.montoya.persistence.Preferences;
import yuc.Endpoint;
import yuc.HeaderProfile;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * 请求头配置冒烟测试：三种粘贴格式都要认得，替换后报文要正确。
 */
public class HeaderSmoke {

    static int failed = 0;

    public static void main(String[] args) throws Exception {
        // 1) 整段请求报文（带 body，body 里的 JSON 不能被当成头）
        String request = "POST /api/save HTTP/1.1\r\n"
                + "Host: h5.demo.com.cn\r\n"
                + "Authorization: Bearer abc123\r\n"
                + "Cookie: sid=xyz; theme=dark\r\n"
                + "Content-Type: application/json\r\n"
                + "Content-Length: 13\r\n"
                + "\r\n"
                + "{\"a\": 1, \"b\": 2}";
        List<String[]> h1 = HeaderProfile.parse(request);
        check("请求报文识别 3 条（Host/CL 被跳过）", h1.size() == 3);
        check("保留了 Authorization", has(h1, "Authorization", "Bearer abc123"));
        check("保留了 Cookie", has(h1, "Cookie", "sid=xyz; theme=dark"));
        check("没有把 body 当头部", !hasName(h1, "a") && !hasName(h1, "b"));

        // 2) 整段响应报文
        String response = "HTTP/1.1 200 OK\r\n"
                + "Server: nginx\r\n"
                + "X-Trace: 9f2\r\n"
                + "\r\n"
                + "{\"code\":0}";
        List<String[]> h2 = HeaderProfile.parse(response);
        check("响应报文识别 2 条", h2.size() == 2);
        check("状态行没被当头", !hasName(h2, "HTTP/1.1 200 OK"));

        // 3) 裸 Key: Value
        List<String[]> h3 = HeaderProfile.parse("X-Token: t-1\nUser-Agent: yuc/1.0\n\n");
        check("裸 Key: Value 识别 2 条", h3.size() == 2);
        check("空行后不再解析", HeaderProfile.parse("A: 1\n\nB: 2").size() == 1);

        // 4) 垃圾输入
        check("空文本 → 0 条", HeaderProfile.parse("").isEmpty());
        check("null → 0 条", HeaderProfile.parse(null).isEmpty());
        check("没有冒号的行被忽略", HeaderProfile.parse("just some text").isEmpty());
        check("JSON 行不被误认", HeaderProfile.parse("\"name\": \"x\"").isEmpty());

        // 5) 替换效果
        Endpoint ep = new Endpoint("POST", "https", "h5.demo.com.cn", 443, "/api/save",
                "https://h5.demo.com.cn/api/save", "Proxy",
                new ArrayList<String[]>(), new ArrayList<String[]>(),
                List.<String[]>of(new String[]{"X-From-Sample", "1"}),
                "{\"k\":\"v\"}".getBytes(StandardCharsets.UTF_8),
                "application/json", "{\"k\":\"v\"}",
                "application/json", "{\"ok\":true}", 200, 20);

        String withSample = new String(ep.rawRequestBytes(), StandardCharsets.UTF_8);
        check("没有配置时用样本头", withSample.contains("X-From-Sample: 1"));
        check("样本头里没有 Authorization", !withSample.contains("Authorization"));

        String replaced = new String(ep.rawRequestBytes(h1), StandardCharsets.UTF_8);
        check("配置后整组替换（样本头消失）", !replaced.contains("X-From-Sample"));
        check("配置的 Authorization 生效", replaced.contains("Authorization: Bearer abc123"));
        check("配置的 Cookie 生效", replaced.contains("Cookie: sid=xyz; theme=dark"));
        check("Host 由插件重算，不重复", count(replaced, "Host:") == 1);
        check("Host 用的是样本域名", replaced.contains("Host: h5.demo.com.cn"));
        check("Content-Length 按实际 body 重算", replaced.contains("Content-Length: 9"));
        check("请求行保留原始 query", replaced.startsWith("POST /api/save HTTP/1.1"));
        check("body 在最后", replaced.endsWith("{\"k\":\"v\"}"));

        // 6) 配置里没写 Content-Type 时，从样本补
        List<String[]> onlyAuth = HeaderProfile.parse("Authorization: Bearer only-auth");
        String noCt = new String(ep.rawRequestBytes(onlyAuth), StandardCharsets.UTF_8);
        check("缺 Content-Type 时从样本补", noCt.contains("Content-Type: application/json"));

        // 7) 存取（preferences）
        final String[] saved = new String[1];
        Preferences prefs = stub(Preferences.class, (n, a) -> {
            if ("setString".equals(n)) {
                saved[0] = String.valueOf(a[1]);
                return null;
            }
            if ("getString".equals(n)) {
                return saved[0];
            }
            return null;
        });
        Persistence p = stub(Persistence.class, (n, a) -> "preferences".equals(n) ? prefs : null);
        MontoyaApi api = stub(MontoyaApi.class, (n, a) -> "persistence".equals(n) ? p : null);

        HeaderProfile profile = new HeaderProfile(api);
        check("初始为空", profile.isEmpty());
        profile.save("X-A: 1\nX-B: 2");
        check("保存后解析出 2 条", profile.headers().size() == 2);
        check("已写入 preferences", saved[0] != null && saved[0].contains("X-A: 1"));

        HeaderProfile reloaded = new HeaderProfile(api);
        check("重建实例能读回", reloaded.headers().size() == 2);

        profile.save("");
        check("清空后为空", profile.isEmpty());

        System.out.println(HeaderProfile.describe(request));
        System.out.println(failed == 0 ? "HEADER PASS" : "HEADER FAILED: " + failed);
        if (failed > 0) {
            System.exit(1);
        }
    }

    static boolean has(List<String[]> hs, String name, String value) {
        for (String[] h : hs) {
            if (h[0].equals(name) && h[1].equals(value)) {
                return true;
            }
        }
        return false;
    }

    static boolean hasName(List<String[]> hs, String name) {
        for (String[] h : hs) {
            if (h[0].equals(name)) {
                return true;
            }
        }
        return false;
    }

    static int count(String s, String sub) {
        int n = 0;
        int i = 0;
        while ((i = s.indexOf(sub, i)) >= 0) {
            n++;
            i += sub.length();
        }
        return n;
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
        return (T) Proxy.newProxyInstance(HeaderSmoke.class.getClassLoader(), new Class<?>[]{iface}, ih);
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
