import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.persistence.Persistence;
import burp.api.montoya.persistence.Preferences;
import yuc.Endpoint;
import yuc.EndpointStore;
import yuc.Params;
import yuc.TemplateBuilder;

import java.io.File;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

/**
 * 持久化冒烟测试：验证「关掉 Burp 再打开，接口还在」，以及升级时把老的
 * 域名_端口.json 读回内存（否则第一次落盘就会整文件覆盖掉）。
 */
public class DbSmoke {

    static int failed = 0;

    public static void main(String[] args) throws Exception {
        File dir = Files.createTempDirectory("yuc-db").toFile();

        // ---------------- 第一次运行：抓两条，落盘
        EndpointStore s1 = store(dir);
        check("新目录默认空库", s1.endpointCount() == 0);
        check("库文件已创建", new File(dir, EndpointStore.DB_FILE).exists());

        s1.add(new Endpoint("GET", "https", "h5.demo.com.cn", 443, "/api/v1/list",
                "https://h5.demo.com.cn/api/v1/list?page=1", "Proxy",
                List.<String[]>of(new String[]{"page", "1"}), new ArrayList<String[]>(),
                "application/json", "", "application/json",
                "{\"code\":0,\"data\":{\"list\":[{\"id\":10086}]}}", 200, 100));
        s1.add(new Endpoint("POST", "https", "api.example.com", 443, "/v1/save",
                "https://api.example.com/v1/save", "Proxy",
                new ArrayList<String[]>(), new ArrayList<String[]>(),
                "application/json", "{\"user\":{\"name\":\"张三\"},\"tags\":[\"a\",\"b\"],\"items\":[{\"sku\":\"a\"}]}",
                "application/json", "{\"ok\":true}", 200, 20));
        s1.flushAll();
        check("落盘后内存有 2 条", s1.endpointCount() == 2);
        s1.shutdown();

        // ---------------- 第二次运行：应该原样加载回来
        EndpointStore s2 = store(dir);
        check("重启后接口还在", s2.endpointCount() == 2);

        Endpoint list = find(s2, "/api/v1/list");
        check("重启后路径还在", list != null);
        check("重启后域名还在", s2.domain("h5.demo.com.cn:443") != null);
        check("重启后 query 参数还在", list != null && list.query.size() == 1
                && list.query.get(0)[0].equals("page"));
        check("重启后请求头不存（符合设计）", list != null && list.requestHeaders.isEmpty());
        check("重启后响应正文不存（省空间）", list != null && list.responseBody.isEmpty());
        check("重启后请求行仍带 query", list != null
                && firstLine(list.rawRequestBytes()).equals("GET /api/v1/list?page=1 HTTP/1.1"));

        // 响应字段靠 DB 里那张 params 表撑起界面
        List<Params.ParamStat> stats2 = Params.stats(s2.endpoints("h5.demo.com.cn:443"));
        boolean hasCode = false;
        for (Params.ParamStat st : stats2) {
            if ("响应".equals(st.where) && st.name.equals("code")) {
                hasCode = true;
            }
        }
        check("重启后响应字段仍可见", hasCode);

        Endpoint save = find(s2, "/v1/save");
        check("重启后请求体还在", save != null && save.requestBody.contains("张三"));
        check("重启后能重编出请求头行", save != null
                && new String(save.rawRequestBytes(), StandardCharsets.UTF_8).startsWith("POST /v1/save HTTP/1.1"));
        check("重编的报文带 body", save != null
                && new String(save.rawRequestBytes(), StandardCharsets.UTF_8).endsWith("}"));
        check("重启后参数表能重新解析 body",
                save != null && Params.templateParams(save).size() > 0);
        // 数组容器那一行不单独落库：它跟着 request_body 一起存，重启后重新算得出来
        check("重启后数组容器行仍是 [sku]",
                Params.stats(List.of(save)).stream()
                        .anyMatch(st -> st.fullPath.equals("items") && st.payload.equals("[sku]")));
        check("重启后标量数组不冒充容器行",
                Params.stats(List.of(save)).stream().noneMatch(st -> st.fullPath.equals("tags")));

        // 导出能力仍在
        String json = yuc.MiniJson.pretty(TemplateBuilder.domainDoc("https", "h5.demo.com.cn", 443,
                s2.endpoints("h5.demo.com.cn:443")));
        check("重启后仍能导出模板", json.contains("/api/v1/list"));
        s2.shutdown();

        // ---------------- 清空之后，重启应该是空的
        EndpointStore s3 = store(dir);
        s3.clearAll();
        s3.shutdown();
        EndpointStore s4 = store(dir);
        check("清空后重启为空", s4.endpointCount() == 0);
        s4.shutdown();

        // ---------------------------- 老数据迁移
        File legacyDir = Files.createTempDirectory("yuc-legacy").toFile();
        String legacy = "{\n"
                + "  \"base\": {\"scheme\": \"https\", \"host\": \"md.demo.cn\", \"port\": 443},\n"
                + "  \"items\": [{\n"
                + "    \"id\": \"get-api-user-detail\",\n"
                + "    \"name\": \"GET /api/user/detail\",\n"
                + "    \"method\": \"GET\",\n"
                + "    \"uri\": \"/api/user/detail?uid=1\",\n"
                + "    \"params\": [\n"
                + "      {\"in\": \"query\", \"name\": \"uid\", \"value\": \"1\"},\n"
                + "      {\"in\": \"json\", \"name\": \"user.name\", \"value\": \"张三\"},\n"
                + "      {\"in\": \"json\", \"name\": \"user.bigId\", \"value\": \"9007199254740993\", \"type\": \"string\"},\n"
                + "      {\"in\": \"json\", \"name\": \"tags\", \"value\": [\"a\", \"b\"], \"type\": \"array\"}\n"
                + "    ]\n"
                + "  }, {\n"
                + "    \"id\": \"post-api-login\",\n"
                + "    \"name\": \"POST /api/login\",\n"
                + "    \"method\": \"POST\",\n"
                + "    \"uri\": \"/api/login\",\n"
                + "    \"params\": [\n"
                + "      {\"in\": \"form\", \"name\": \"user\", \"value\": \"admin\"},\n"
                + "      {\"in\": \"form\", \"name\": \"pwd\", \"value\": \"a b\"}\n"
                + "    ]\n"
                + "  }]\n"
                + "}";
        Files.writeString(new File(legacyDir, "md.demo.cn_443.json").toPath(), legacy, StandardCharsets.UTF_8);

        EndpointStore s5 = store(legacyDir);
        check("老 json 被导入", s5.endpointCount() == 2);
        check("导入的域名正确", s5.domain("md.demo.cn:443") != null);

        Endpoint detail = find(s5, "/api/user/detail");
        check("导入的 query 还在", detail != null && detail.query.size() == 1);
        check("导入时重建了 JSON 请求体", detail != null && detail.requestBody.contains("\"user\""));
        check("重建的嵌套字段正确", detail != null && detail.requestBody.contains("张三"));
        check("重建的数组原样保留", detail != null && detail.requestBody.contains("[\"a\",\"b\"]"));
        check("大整数没退化成数字", detail != null && detail.requestBody.contains("9007199254740993"));

        Endpoint login = find(s5, "/api/login");
        check("表单能重建", login != null && login.requestBody.contains("user=admin"));
        check("表单里的空格按 form 规则编码", login != null && login.requestBody.contains("pwd=a+b"));
        check("表单 Content-Type 正确", login != null
                && "application/x-www-form-urlencoded".equals(login.requestContentType));

        File backup = null;
        File[] sub = legacyDir.listFiles(File::isDirectory);
        if (sub != null) {
            for (File f : sub) {
                if (f.getName().startsWith("backup-")) {
                    backup = f;
                }
            }
        }
        check("迁移前已备份原文件", backup != null);
        check("备份里有原始 json", backup != null && backup.listFiles().length == 1);
        check("导入后已入库", new File(legacyDir, EndpointStore.DB_FILE).exists());
        s5.shutdown();

        // 再开一次：这次应该走数据库，而不是重复导入/重复备份
        EndpointStore s6 = store(legacyDir);
        check("第二次启动仍只有 2 条（没重复导入）", s6.endpointCount() == 2);
        int backups = 0;
        File[] sub2 = legacyDir.listFiles(File::isDirectory);
        if (sub2 != null) {
            for (File f : sub2) {
                if (f.getName().startsWith("backup-")) {
                    backups++;
                }
            }
        }
        check("没有重复备份", backups == 1);
        s6.shutdown();

        System.out.println(failed == 0 ? "DB PASS" : "DB FAILED: " + failed);
        if (failed > 0) {
            System.exit(1);
        }
    }

    static String firstLine(byte[] bytes) {
        String s = new String(bytes, StandardCharsets.UTF_8);
        int i = s.indexOf("\r\n");
        return i < 0 ? s : s.substring(0, i);
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

    /** 造一个把「存储目录」指向 dir 的 store。 */
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
        return (T) Proxy.newProxyInstance(DbSmoke.class.getClassLoader(), new Class<?>[]{iface}, ih);
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
