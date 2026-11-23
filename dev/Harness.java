import yuc.Endpoint;
import yuc.EndpointStore;
import yuc.MiniJson;
import yuc.Params;
import yuc.TemplateBuilder;
import yuc.Urls;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** 离线自测：不依赖 Burp，跑纯逻辑（解析/规则/模板生成/去重落盘）。 */
public class Harness {

    static int failed = 0;

    public static void main(String[] args) throws Exception {
        Files.createDirectories(java.nio.file.Path.of("dev/gen"));
        json();
        urls();
        template();
        display();
        replay();
        shapes();
        store();
        System.out.println(failed == 0 ? "\nALL PASS" : "\nFAILED: " + failed);
        if (failed > 0) {
            System.exit(1);
        }
    }

    static void json() {
        String src = "{\"a\":[1,2,{\"b\":\"中文\\n\"}],\"big\":9007199254740993,\"n\":null,\"t\":true,\"d\":1.5}";
        Object v = MiniJson.parse(src);
        String out = MiniJson.write(v);
        check("json 大类", v instanceof Map);
        Map<?, ?> m = (Map<?, ?>) v;
        check("json 大整数不丢精度", String.valueOf(m.get("big")).equals("9007199254740993"));
        check("json 往返稳定", MiniJson.write(MiniJson.parse(out)).equals(out));
        check("json 中文转义", MiniJson.write("中文").equals("\"中文\""));
        check("json 非法输入不抛", MiniJson.tryParse("{oops") == null);
        System.out.println("[json] " + out);
    }

    static void urls() {
        check("静态 .js 排除", !Urls.looksLikeApi(Urls.path("https://a.com/static/app.js?v=1")));
        check("json 后缀排除", !Urls.looksLikeApi("/v1/user.json"));
        check("根路径排除", !Urls.looksLikeApi("/"));
        check("正常接口保留", Urls.looksLikeApi("/api/user/list"));
        check("尾斜杠接口保留", Urls.looksLikeApi("/api/user/"));
        check("path 去 query", Urls.path("https://a.com:8443/api/x?id=1#frag").equals("/api/x"));
        check("query 解析", Urls.queryPairs("a=1&b=%E4%B8%AD&flag").size() == 3);
        check("pct 解码中文", Urls.queryPairs("n=%E5%BC%A0%E4%B8%89").get(0)[1].equals("张三"));
        check("pct 不把 + 当空格", Urls.pctDecode("a+b").equals("a+b"));
        check("cookie 解析", Urls.cookiePairs("a=1; b=2").size() == 2);
        check("文件名安全", Urls.safeFileName("a:b/c").equals("a_b_c"));
    }

    static void template() throws Exception {
        List<String[]> query = new ArrayList<>();
        query.add(new String[]{"page", "1"});
        query.add(new String[]{"size", "20"});
        String req = "{\"user\":{\"name\":\"张三\",\"bigId\":9007199254740993,\"meta\":{}},"
                + "\"tags\":[\"a\",\"b\"],\"orders\":[{\"id\":\"A-1\"}],\"note\":null,\"a.b\":1}";
        String resp = "{\"code\":0,\"data\":{\"list\":[{\"id\":1,\"name\":\"x\"}],\"total\":1},\"empty\":[]}";

        Endpoint ep = new Endpoint("POST", "https", "api.example.com", 443,
                "/v1/users/10086", "https://api.example.com/v1/users/10086?page=1&size=20", "Proxy",
                query, Urls.cookiePairs("session=abc"),
                "application/json; charset=utf-8", req,
                "application/json", resp, 200, 1234);

        Map<String, Object> doc = TemplateBuilder.domainDoc("https", "api.example.com", 443, List.of(ep));
        String json = MiniJson.pretty(doc);
        Files.writeString(new File("dev/gen/template-doc.json").toPath(), json, StandardCharsets.UTF_8);
        System.out.println("[template]\n" + json);
        check("模板含 base", json.contains("\"base\""));
        check("模板 uri 无 query", json.contains("\"uri\": \"/v1/users/10086\""));
        check("查询参数进表", json.contains("\"in\": \"query\""));
        check("cookie 进表", json.contains("\"in\": \"cookie\""));
        check("数组整棵一行", json.contains("\"type\": \"array\""));
        check("大整数转字符串", json.contains("\"value\": \"9007199254740993\""));
        check("点号键转义", json.contains("[\\\"a.b\\\"]"));
        check("null 带类型", json.contains("\"type\": \"null\""));

        List<Params.ParamStat> stats = Params.stats(List.of(ep));
        boolean hasRespKey = stats.stream().anyMatch(s -> s.fullPath.equals("data.list[].name"));
        check("完整路径保留在 fullPath 里", hasRespKey);
        check("界面只留最后一层 key", stats.stream().anyMatch(s -> s.name.equals("name")));
        check("查询名保持字面量", stats.stream().anyMatch(s -> s.name.equals("page")));
        check("引号键还原成 a.b", stats.stream().anyMatch(s -> s.name.equals("a.b")));
        check("统计里不出现完整层级", stats.stream().noneMatch(s -> s.name.startsWith("data.")));
        System.out.println("[params] " + stats.size() + " 个：" + stats.stream().map(s -> s.name).toList());

        // -------- 数组容器自己也占一行：{"query":[{…}]} 里 query 不能只当"前缀"
        String req2 = "{\"dataModel\":\"METRIC\",\"query\":[{\"identifier\":\"A\","
                + "\"select\":[{\"fn\":\"AVG\",\"p\":\"db.x\"}],"
                + "\"where\":{\"condition\":[{\"k\":\"a\"}],\"logical\":\"AND\"}}],\"entity\":[]}";
        Endpoint ep2 = new Endpoint("POST", "https", "api.example.com", 443, "/v1/metric",
                "https://api.example.com/v1/metric", "Repeater",
                new ArrayList<>(), new ArrayList<>(), "application/json", req2,
                "application/json", "{}", 200, 10);
        List<Params.ParamStat> s2 = Params.stats(List.of(ep2));
        System.out.println("[array] " + s2.stream().map(s -> s.name + "=" + s.payload).toList());

        Params.ParamStat q = s2.stream().filter(s -> s.name.equals("query")).findFirst().orElse(null);
        check("数组参数 query 自己也是一行", q != null);
        check("query 的值 = 元素的键清单", q != null && q.payload.equals("[identifier,select,where]"));
        check("嵌套数组 select 也有自己一行",
                s2.stream().anyMatch(s -> s.name.equals("select") && s.payload.equals("[fn,p]")));
        check("数组里嵌的数组按 query[].where.condition 记",
                s2.stream().anyMatch(s -> s.name.equals("condition") && s.fullPath.endsWith(".condition")));
        Params.ParamStat where = s2.stream().filter(s -> s.fullPath.equals("query[].where")).findFirst().orElse(null);
        check("对象也补一行（where 不是纯分层）", where != null);
        check("对象的值 = 它的键清单 {condition,logical}",
                where != null && where.payload.equals("{condition,logical}"));
        check("数组用 [] 包、对象用 {} 包，一眼能分清",
                where != null && where.payload.startsWith("{")
                        && s2.stream().anyMatch(s -> s.fullPath.equals("query") && s.payload.startsWith("[")));
        check("数组元素那个对象不重复补行", s2.stream().noneMatch(s -> s.fullPath.equals("query[]")));
        check("空数组不补容器行", s2.stream().noneMatch(s -> s.fullPath.equals("entity")));
        check("标量数组不补容器行", stats.stream().noneMatch(s -> s.fullPath.equals("tags")));
        check("空对象不补容器行（user.meta 只有空值那条老行）",
                stats.stream().noneMatch(s -> s.fullPath.equals("user.meta") && s.payload.startsWith("{")));
        check("嵌套对象补在 request 里（user）",
                stats.stream().anyMatch(s -> s.fullPath.equals("user")
                        && s.payload.equals("{name,bigId,meta}")));
        check("响应里的对象也补（data）",
                stats.stream().anyMatch(s -> s.fullPath.equals("data")
                        && s.payload.equals("{list,total}")));
        check("标量数组的叶子行还在（tags[]）",
                stats.stream().anyMatch(s -> s.fullPath.equals("tags[]")));
        check("对象数组 orders 补上了",
                stats.stream().anyMatch(s -> s.fullPath.equals("orders") && s.payload.equals("[id]")));
        check("叶子和容器同时在：query[].identifier 还在",
                s2.stream().anyMatch(s -> s.fullPath.equals("query[].identifier")));

        // 这些补出来的行只给参数表看，模板必须一个字节都不变：query 仍是"整棵数组一行"
        String doc2 = MiniJson.pretty(TemplateBuilder.domainDoc("https", "api.example.com", 443, List.of(ep2)));
        check("模板里 query 还是整棵 array 一行",
                doc2.contains("\"name\": \"query\"") && doc2.contains("\"type\": \"array\""));
        check("容器的键清单不进模板", !doc2.contains("identifier,select"));
    }

    static void store() throws Exception {
        File dir = Files.createTempDirectory("yuc-test").toFile();
        // 直接指定目录：不能让构造过程去读真实的 ~/yuc-output
        EndpointStore store = new EndpointStore(null, dir);
        store.setRecording(true);

        store.add(sample("/api/list", "GET", 100, "{\"q\":1}", "{\"a\":1}"));
        store.add(sample("/api/list", "GET", 900, "{\"q\":1,\"size\":20}", "{\"a\":1,\"b\":2}"));
        // 参数名要和前两档都不一样，才算"新形状"——同形状只换长度会被判重挡掉
        store.add(sample("/api/list", "GET", 50, "{\"q\":1,\"only\":1}", "{\"a\":0}"));
        check("同接口按长度留档，主样本是最长的",
                store.endpoints("api.example.com:443").get(0).responseLength == 900);
        check("更短的新长度作为副档保留",
                store.endpoints("api.example.com:443").get(0).sampleCount() == 3);
        store.add(sample("/api/list", "GET", 100, "{\"a\":9}"));
        check("同长度重复不再记一条",
                store.endpoints("api.example.com:443").get(0).sampleCount() == 3);
        check("同长度重复计入跳过", store.skipped() == 1);
        check("不同参数值归为同一接口", store.endpoints("api.example.com:443").size() == 1);

        store.flushAll();
        File file = new File(dir, "api.example.com_443.json");
        check("落盘文件名 域名_端口.json", file.isFile());
        String written = Files.readString(file.toPath(), StandardCharsets.UTF_8);
        check("落盘内容是模板", written.contains("\"items\""));
        System.out.println("[store] " + file.getAbsolutePath());
        System.out.println(written);
        Files.writeString(new File("dev/gen/store-doc.json").toPath(), written, StandardCharsets.UTF_8);
    }

    static void shapes() throws Exception {
        String boundary = "----X";
        String multipart = "--" + boundary + "\r\n"
                + "Content-Disposition: form-data; name=\"remark\"\r\n\r\n头像\r\n"
                + "--" + boundary + "\r\n"
                + "Content-Disposition: form-data; name=\"file\"; filename=\"a.png\"\r\n"
                + "Content-Type: image/png\r\n\r\n<binary>\r\n"
                + "--" + boundary + "--\r\n";

        List<Endpoint> eps = new ArrayList<>();
        eps.add(new Endpoint("POST", "https", "api.example.com", 443, "/v1/login",
                "https://api.example.com/v1/login", "Proxy", new ArrayList<>(),
                new ArrayList<String[]>(),
                "application/x-www-form-urlencoded", "username=admin&password=p%40ss+w0rd",
                "application/json", "{\"token\":\"t\"}", 200, 12));
        eps.add(new Endpoint("POST", "https", "api.example.com", 443, "/v1/upload",
                "https://api.example.com/v1/upload", "Proxy", new ArrayList<>(),
                new ArrayList<String[]>(),
                "multipart/form-data; boundary=" + boundary, multipart,
                "application/json", "{\"ok\":true}", 200, 11));
        eps.add(new Endpoint("POST", "https", "api.example.com", 443, "/v1/push",
                "https://api.example.com/v1/push", "Repeater", new ArrayList<>(),
                new ArrayList<String[]>(),
                "application/xml", "<root id=\"1\"><name>张三</name></root>",
                "application/json", "{\"ok\":true}", 200, 11));
        eps.add(new Endpoint("POST", "https", "api.example.com", 443, "/v1/batch",
                "https://api.example.com/v1/batch", "Repeater", new ArrayList<>(),
                new ArrayList<String[]>(),
                "application/json", "[{\"name\":\"甲\"},{\"name\":\"乙\"}]",
                "application/json", "{\"ok\":true}", 200, 11));

        String json = MiniJson.pretty(TemplateBuilder.domainDoc("https", "api.example.com", 443, eps));
        Files.writeString(new File("dev/gen/shapes-doc.json").toPath(), json, StandardCharsets.UTF_8);
        System.out.println("[shapes]\n" + json);
        multipartPlaceholder();
        check("表单行 in:form", json.contains("\"in\": \"form\""));
        check("表单值解出 @", json.contains("p@ss w0rd"));
        check("multipart 文件 part", json.contains("\"./a.png\""));
        check("raw 行 mediaType", json.contains("application/xml"));
        check("顶层数组用空名字", json.contains("\"name\": \"\""));
    }

    static void display() {
        check("左 2 段", Urls.displayPath("/aaa/bbb/ccc", Urls.PATH_LEFT, 2).equals("/aaa/bbb"));
        check("右 2 段", Urls.displayPath("/aaa/bbb/ccc", Urls.PATH_RIGHT, 2).equals("/bbb/ccc"));
        check("完整模式不截断", Urls.displayPath("/aaa/bbb/ccc", Urls.PATH_FULL, 2).equals("/aaa/bbb/ccc"));
        check("段数不够时不截断", Urls.displayPath("/aaa", Urls.PATH_LEFT, 3).equals("/aaa"));
        check("lastKey 取末层", Params.lastKey("metadata.schema.properties.size.title").equals("title"));
        check("lastKey 去数组", Params.lastKey("data.list[].id").equals("id"));
        check("lastKey 引号键", Params.lastKey("a.[\"x.y\"]").equals("x.y"));
    }

    static void replay() {
        List<String[]> headers = new ArrayList<>();
        headers.add(new String[]{"Host", "api.example.com"});
        headers.add(new String[]{"Content-Type", "application/json"});
        headers.add(new String[]{"Content-Length", "999"});
        headers.add(new String[]{"Authorization", "Bearer t"});
        headers.add(new String[]{"Connection", "close"});
        byte[] body = "{\"a\":1}".getBytes(StandardCharsets.UTF_8);
        Endpoint ep = new Endpoint("POST", "https", "api.example.com", 443, "/v1/save",
                "https://api.example.com/v1/save?x=1&y=2", "Proxy",
                Urls.queryPairs("x=1&y=2"), Urls.cookiePairs("s=1"),
                headers, body, "application/json", "{\"a\":1}", "application/json", "{}", 200, 2);
        String raw = new String(ep.rawRequestBytes(), StandardCharsets.UTF_8);
        System.out.println("[replay]\n" + raw);
        check("请求行带原始 query", raw.startsWith("POST /v1/save?x=1&y=2 HTTP/1.1\r\n"));
        check("Host 只出现一次", raw.indexOf("Host:") == raw.lastIndexOf("Host:"));
        check("旧 Content-Length 被丢掉", !raw.contains("Content-Length: 999"));
        check("Content-Length 重新算", raw.contains("Content-Length: 7"));
        check("保留 Authorization", raw.contains("Authorization: Bearer t"));
        check("丢掉 Connection", !raw.contains("Connection:"));
        check("body 在末尾", raw.endsWith("{\"a\":1}"));
    }

    static void multipartPlaceholder() {
        String longVal = "x".repeat(60);
        String body = "--B\r\nContent-Disposition: form-data; name=\"desc\"\r\n\r\n" + longVal
                + "\r\n--B\r\nContent-Disposition: form-data; name=\"f\"; filename=\"short.txt\"\r\n\r\nabc\r\n--B--";
        Endpoint ep = new Endpoint("POST", "https", "e.com", 443, "/up", "https://e.com/up", "Proxy",
                new ArrayList<String[]>(), new ArrayList<String[]>(),
                "multipart/form-data; boundary=B", body, "application/json", "{}", 200, 2);
        List<Map<String, Object>> rows = Params.templateParams(ep);
        check("长上传值换成占位符", Params.LONG_VALUE_PLACEHOLDER.equals(rows.get(0).get("value")));
        check("短的文件名保留", "./short.txt".equals(rows.get(1).get("value")));
    }

    static Endpoint sample(String path, String method, long len, String body) {
        return sample(path, method, len, "{\"q\":1}", body);
    }

    /** 请求体可以换，用来造出不同的「参数形状」——形状一样的话新长度会被判重挡掉。 */
    static Endpoint sample(String path, String method, long len, String reqBody, String body) {
        return new Endpoint(method, "https", "api.example.com", 443, path,
                "https://api.example.com" + path + "?page=1", "Repeater",
                List.<String[]>of(new String[]{"page", "1"}), new ArrayList<String[]>(),
                "application/json", reqBody, "application/json", body, 200, len);
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
