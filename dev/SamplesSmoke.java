import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.persistence.Persistence;
import burp.api.montoya.persistence.Preferences;
import yuc.Endpoint;
import yuc.EndpointStore;
import yuc.MiniJson;
import yuc.TemplateBuilder;

import java.io.File;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

/**
 * 「一个接口按响应长度留多档」的自测。
 * <p>
 * 覆盖用户提的两个真实场景：
 * <ul>
 *   <li>A：先 3 参数返 200，删掉一个参数后返 400（更长）→ 主样本变 400，但 3 参数那档还在</li>
 *   <li>B：先 2 参数返 400（更长），加一个参数后返 200 → 主样本仍是 400，新参数留在 200 那档</li>
 * </ul>
 */
public class SamplesSmoke {

    static int failed = 0;
    static final String DK = "h5.demo.com.cn:443";

    public static void main(String[] args) throws Exception {
        scenarioA();
        scenarioB();
        duplicate();
        sameShape();
        cap();
        exportAndDb();

        System.out.println(failed == 0 ? "SAMPLES PASS" : "SAMPLES FAILED: " + failed);
        if (failed > 0) {
            System.exit(1);
        }
    }

    // ------------------------------------------------ A：删参数后变长
    static void scenarioA() throws Exception {
        EndpointStore store = store();
        // 3 个字段，响应 200 字节
        store.add(ep("/api/list", 200, "{\"a\":1,\"b\":2,\"c\":3}", "{\"code\":0}"));
        // 删掉 c 之后返回"全量"，400 字节
        store.add(ep("/api/list", 400, "{\"a\":1,\"b\":2}", "{\"code\":0,\"all\":true}"));

        check("A 仍是一个接口", store.endpoints(DK).size() == 1);
        Endpoint p = store.endpoints(DK).get(0);
        check("A 主样本是最长的 400", p.responseLength == 400);
        check("A 主样本参数是 2 个", p.paramCount() == 2);
        check("A 收下两档", p.sampleCount() == 2);
        Endpoint shortOne = p.samples().get(0);
        check("A 副档是 200 那档", shortOne.responseLength == 200);
        check("A 副档保留完整的 3 个参数", shortOne.paramCount() == 3);
        check("A 每档都能独立还原请求",
                new String(shortOne.rawRequestBytes(), StandardCharsets.UTF_8).contains("\"c\":3"));
        store.shutdown();
    }

    // ------------------------------------------------ B：加参数后变短
    static void scenarioB() throws Exception {
        EndpointStore store = store();
        // 2 个字段，报错页 500 字节
        store.add(ep("/api/user", 500, "{\"a\":1,\"b\":2}", "{\"error\":\"参数不合法\"}"));
        // 补上参数后正常返回 200 字节
        store.add(ep("/api/user", 200, "{\"a\":1,\"b\":2,\"deptId\":9}", "{\"code\":0}"));

        Endpoint p = store.endpoints(DK).get(0);
        check("B 主样本仍是较长的 500", p.responseLength == 500);
        check("B 主样本参数是 2 个", p.paramCount() == 2);
        check("B 新增的那档被记下来了", p.sampleCount() == 2);
        Endpoint good = p.samples().get(0);
        check("B 200 那档在", good.responseLength == 200);
        check("B 新增参数 deptId 有记录",
                good.rawRequestBytes().length > 0
                        && new String(good.rawRequestBytes(), StandardCharsets.UTF_8).contains("deptId"));
        check("B 200 那档参数是 3 个", good.paramCount() == 3);
        store.shutdown();
    }

    // ------------------------------------------------ 同长度不重复
    static void duplicate() throws Exception {
        EndpointStore store = store();
        store.add(ep("/api/x", 300, "{\"a\":1}", "{\"code\":0}"));
        long skip0 = store.skipped();
        store.add(ep("/api/x", 300, "{\"a\":1,\"b\":2}", "{\"code\":1}"));
        store.add(ep("/api/x", 300, "{\"a\":1,\"b\":2,\"c\":3}", "{\"code\":2}"));
        Endpoint p = store.endpoints(DK).get(0);
        check("同长度重复不新增档位", p.sampleCount() == 1);
        check("同长度重复计入跳过", store.skipped() == skip0 + 2);
        check("同长度不刷新参数（保留第一次见到的那份）", p.paramCount() == 1);
        store.shutdown();
    }

    // ------------------------------------------------ 长度变了但参数名没变
    static void sameShape() throws Exception {
        EndpointStore store = store();
        store.add(ep("/api/q", 300, "{\"a\":1,\"b\":2}", "{\"code\":0}"));
        long skip0 = store.skipped();

        // 同一条请求又抓了两次：响应里多了时间戳、长度变了，请求一个参数都没动
        store.add(ep("/api/q", 340, "{\"a\":1,\"b\":2}", "{\"code\":0,\"ts\":1712345678901}"));
        store.add(ep("/api/q", 320, "{\"a\":1,\"b\":2}", "{\"code\":0,\"ts\":1712345678}"));
        Endpoint p = store.endpoints(DK).get(0);
        check("长度变了但参数名没变 → 不新增档位", p.sampleCount() == 1);
        check("参数名重复计入跳过", store.skipped() == skip0 + 2);
        check("主样本还是第一次那档（不因变长而换）", p.responseLength == 300);

        // 只比名字不比值：值全变了、名字没变，仍是同一种形状
        store.add(ep("/api/q", 380, "{\"a\":9,\"b\":8}", "{\"code\":0,\"x\":1}"));
        check("值变了名字没变也不开新档", store.endpoints(DK).get(0).sampleCount() == 1);

        // 多了一个字段 → 形状变了，收下
        store.add(ep("/api/q", 400, "{\"a\":1,\"b\":2,\"deptId\":9}", "{\"code\":0}"));
        check("多一个参数名就收新档", store.endpoints(DK).get(0).sampleCount() == 2);

        // 查询参数：名字相同、值不同 → 同一种形状
        EndpointStore s2 = store();
        s2.add(query("/api/list", "page", "1", 200));
        long skip1 = s2.skipped();
        s2.add(query("/api/list", "page", "2", 260));
        check("查询值不同但名字相同 → 不新增档位",
                s2.endpoints(DK).get(0).sampleCount() == 1 && s2.skipped() == skip1 + 1);
        s2.shutdown();

        // 原始报文体认不出参数名 → 不参与判重，照旧按长度留档
        store.add(raw("/api/xml", 100, "<a>1</a>"));
        store.add(raw("/api/xml", 120, "<a>2</a>"));
        Endpoint xml = find(store, "/api/xml");
        check("原始报文不判重（宁可多留一档）", xml != null && xml.sampleCount() == 2);

        // 模板导入的空壳（长度 0）不能把真样本挡掉
        store.add(ep("/api/tpl", 0, "{\"a\":1}", ""));
        store.add(ep("/api/tpl", 200, "{\"a\":1}", "{\"code\":0}"));
        Endpoint tpl = find(store, "/api/tpl");
        check("长度 0 的空壳不挡真样本", tpl != null && tpl.sampleCount() == 2);
        store.shutdown();
    }

    // ------------------------------------------------ 上限与淘汰
    static void cap() throws Exception {
        EndpointStore store = store();
        for (int i = 0; i < 12; i++) {
            long len = 100 + i * 10L;
            // 每档换一个参数名，才算"新形状"——同形状不同长度现在会被判重挡掉
            store.add(ep("/api/many", len,
                    "{\"a\":" + i + ",\"p" + i + "\":" + i + "}", "{\"code\":" + i + "}"));
        }
        Endpoint p = store.endpoints(DK).get(0);
        check("最多留 " + EndpointStore.MAX_SAMPLES + " 档", p.sampleCount() == EndpointStore.MAX_SAMPLES);
        check("主样本仍是最大长度 210", p.responseLength == 210);
        check("被淘汰的是最旧/最短的那几档", p.samples().get(0).responseLength == 140);

        long skip0 = store.skipped();
        store.add(ep("/api/many", 50, "{\"a\":-1}", "{}"));
        check("满了以后更短的新长度直接丢", store.endpoints(DK).get(0).sampleCount() == 8);
        check("丢弃计入跳过", store.skipped() == skip0 + 1);
        store.shutdown();
    }

    // ------------------------------------------------ 落盘 + 库
    static void exportAndDb() throws Exception {
        File dir = Files.createTempDirectory("yuc-samples").toFile();
        EndpointStore s1 = store(dir);
        s1.add(ep("/api/list", 200, "{\"a\":1,\"b\":2,\"c\":3}", "{\"code\":0}"));
        s1.add(ep("/api/list", 400, "{\"a\":1,\"b\":2}", "{\"code\":0,\"all\":true}"));
        s1.add(ep("/api/other", 120, "{\"z\":1}", "{\"ok\":true}"));
        s1.flushAll();

        // 导出的模板只描述主样本：一个接口一条 item
        String json = Files.readString(new File(dir, "h5.demo.com.cn_443.json").toPath(), StandardCharsets.UTF_8);
        Object doc = MiniJson.parse(json);
        List<?> items = (List<?>) ((java.util.Map<?, ?>) doc).get("items");
        check("模板里接口数仍是 2（不按档膨胀）", items.size() == 2);
        check("模板用的是主样本参数（没有 c）", !json.contains("\"name\": \"c\""));

        // lengths 列是数组格式
        check("endpoints.lengths 存成数组", lengthsOf(dir).equals("[200,400]"));
        s1.shutdown();

        // 重启后三档都在，各自参数不串
        EndpointStore s2 = store(dir);
        Endpoint p = find(s2, "/api/list");
        check("重启后接口还在", p != null);
        check("重启后两档都在", p != null && p.sampleCount() == 2);
        check("重启后主样本是 400", p != null && p.responseLength == 400);
        check("重启后主样本参数 2 个", p != null && p.paramCount() == 2);
        Endpoint shortOne = p == null ? null : p.samples().get(0);
        check("重启后副档 200 还在", shortOne != null && shortOne.responseLength == 200);
        check("重启后副档参数还是 3 个", shortOne != null && shortOne.paramCount() == 3);
        check("重启后副档能重编出 c", shortOne != null
                && new String(shortOne.rawRequestBytes(), StandardCharsets.UTF_8).contains("\"c\":3"));
        check("重启后库里有 3 条样本（2 档 + 另一个接口）", s2.sampleCount() == 3);
        s2.shutdown();

        // 清空要连副档一起清
        EndpointStore s3 = store(dir);
        s3.clearAll();
        s3.shutdown();
        EndpointStore s4 = store(dir);
        check("清空后重启为空", s4.endpointCount() == 0);
        s4.shutdown();
    }

    // ---------------------------------------------------------------- 工具

    static Endpoint ep(String path, long len, String requestBody, String responseBody) {
        return new Endpoint("POST", "https", "h5.demo.com.cn", 443, path,
                "https://h5.demo.com.cn" + path, "Proxy",
                new ArrayList<>(), new ArrayList<>(),
                "application/json", requestBody,
                "application/json", responseBody, 200, len);
    }

    /** 只有一对查询参数、没有请求体的样本。 */
    static Endpoint query(String path, String name, String value, long len) {
        return new Endpoint("GET", "https", "h5.demo.com.cn", 443, path,
                "https://h5.demo.com.cn" + path + "?" + name + "=" + value, "Proxy",
                List.<String[]>of(new String[]{name, value}), new ArrayList<String[]>(),
                null, "", "application/json", "{\"code\":0}", 200, len);
    }

    /** 原始报文体（XML 之类）：认不出参数名，判重时不参与。 */
    static Endpoint raw(String path, long len, String body) {
        return new Endpoint("POST", "https", "h5.demo.com.cn", 443, path,
                "https://h5.demo.com.cn" + path, "Proxy",
                new ArrayList<>(), new ArrayList<>(),
                "text/xml", body,
                "text/xml", "<ok/>", 200, len);
    }

    /** 直接开库读 lengths 列，确认它真的是 JSON 数组。 */
    static String lengthsOf(File dir) throws Exception {
        Class.forName("org.sqlite.JDBC");
        String url = "jdbc:sqlite:" + new File(dir, EndpointStore.DB_FILE).getAbsolutePath().replace('\\', '/');
        try (Connection c = DriverManager.getConnection(url);
             Statement s = c.createStatement();
             ResultSet rs = s.executeQuery(
                     "SELECT lengths FROM endpoints WHERE path='/api/list'")) {
            return rs.next() ? rs.getString(1) : "";
        }
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

    static EndpointStore store() throws Exception {
        return store(Files.createTempDirectory("yuc-samples").toFile());
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
        return (T) Proxy.newProxyInstance(SamplesSmoke.class.getClassLoader(), new Class<?>[]{iface}, ih);
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
