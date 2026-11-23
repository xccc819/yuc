import yuc.Endpoint;
import yuc.TemplateImport;
import yuc.Urls;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * 还原到 Repeater 时，URL 里 {@code ?} 后面的参数到底保不保真。
 * <p>
 * 两条路径要分开验证：
 * <ul>
 *   <li><b>实时抓包</b>：url 里有原始 query 串 → 必须一个字节都不改（{@code +}、{@code %20}、重复键、裸参数）</li>
 *   <li><b>从模板/数据库恢复</b>：只有解码后的参数表 → 必须重新拼回去，且编码规则要对（空格是 {@code %20} 不是 {@code +}）</li>
 * </ul>
 */
public class UrlSmoke {

    static int failed = 0;

    public static void main(String[] args) {
        // ---------------------------------------------- 实时抓包：原始串原样
        same("普通两组参数", "https://h5.aep.com.cn/api/list?page=1&size=10",
                "GET /api/list?page=1&size=10 HTTP/1.1");
        same("query 里的 + 是字面加号，不许变 %20 或空格",
                "https://h5.aep.com.cn/api/list?kw=a+b",
                "GET /api/list?kw=a+b HTTP/1.1");
        same("中文保持百分号编码", "https://h5.aep.com.cn/api/list?n=%E4%B8%AD",
                "GET /api/list?n=%E4%B8%AD HTTP/1.1");
        same("百分号编码大小写不改", "https://h5.aep.com.cn/api/list?n=%e4%b8%ad",
                "GET /api/list?n=%e4%b8%ad HTTP/1.1");
        same("重复键一个不少", "https://h5.aep.com.cn/api/list?tag=x&tag=y",
                "GET /api/list?tag=x&tag=y HTTP/1.1");
        same("裸参数（没有 =）保留", "https://h5.aep.com.cn/api/list?flag&page=1",
                "GET /api/list?flag&page=1 HTTP/1.1");
        same("空值保留 =", "https://h5.aep.com.cn/api/list?a=1&b=",
                "GET /api/list?a=1&b= HTTP/1.1");
        same("值里的 & 是 %26，不能再被拆开", "https://h5.aep.com.cn/api/list?q=a%26b%3Dc",
                "GET /api/list?q=a%26b%3Dc HTTP/1.1");
        same("路径里的 ; 与 ~ 不受影响", "https://h5.aep.com.cn/api/v1.0/list~x?x=1",
                "GET /api/v1.0/list~x?x=1 HTTP/1.1");
        same("没有 query 就不加问号", "https://h5.aep.com.cn/api/list",
                "GET /api/list HTTP/1.1");

        // ---------------------------------------------- 从模板恢复：只有参数表
        String json = "{\"base\":{\"scheme\":\"https\",\"host\":\"h5.aep.com.cn\",\"port\":443},"
                + "\"items\":[{\"id\":\"a\",\"name\":\"GET /api/list\",\"method\":\"GET\",\"uri\":\"/api/list\","
                + "\"params\":["
                + "{\"in\":\"query\",\"name\":\"page\",\"value\":\"1\"},"
                + "{\"in\":\"query\",\"name\":\"kw\",\"value\":\"a b\"},"
                + "{\"in\":\"query\",\"name\":\"n\",\"value\":\"中\"},"
                + "{\"in\":\"query\",\"name\":\"q\",\"value\":\"a&b=c\"},"
                + "{\"in\":\"query\",\"name\":\"tag\",\"value\":\"x\"},"
                + "{\"in\":\"query\",\"name\":\"tag\",\"value\":\"y\"},"
                + "{\"in\":\"query\",\"name\":\"plus\",\"value\":\"a+b\"},"
                + "{\"in\":\"json\",\"name\":\"body\",\"value\":1}]}]}";
        Endpoint imp = TemplateImport.parse(json).get(0);
        String target = imp.requestTarget();
        check("恢复后请求行带 query", target.startsWith("/api/list?"));
        check("普通参数在", target.contains("page=1"));
        check("空格编成 %20（不是 +）", target.contains("kw=a%20b"));
        check("中文编成 UTF-8 百分号", target.contains("n=%E4%B8%AD"));
        check("值里的 & 与 = 被编码", target.contains("q=a%26b%3Dc"));
        check("重复键都拼回去", target.contains("tag=x") && target.contains("tag=y"));
        check("字面 + 编成 %2B", target.contains("plus=a%2Bb"));
        check("url 字段本身也补上了 query", imp.url.contains("?" ) && imp.url.contains("page=1"));

        String line = firstLine(imp.rawRequestBytes());
        check("拼出的请求行与 requestTarget 一致", line.equals("GET " + target + " HTTP/1.1"));
        check("恢复的样本 Host 正确", new String(imp.rawRequestBytes(), StandardCharsets.UTF_8)
                .contains("Host: h5.aep.com.cn"));

        // uri 自带 query（有些模板这么写）也要认
        String json2 = "{\"base\":{\"scheme\":\"https\",\"host\":\"api.example.com\",\"port\":443},"
                + "\"items\":[{\"id\":\"b\",\"name\":\"GET /v1/x\",\"method\":\"GET\","
                + "\"uri\":\"/v1/x?from=uri&k=1\",\"params\":[]}]}";
        Endpoint imp2 = TemplateImport.parse(json2).get(0);
        check("uri 自带的 query 被拆进 url", imp2.url.endsWith("/v1/x?from=uri&k=1"));
        check("uri 自带的 query 也出现在参数表", imp2.query.size() == 2);
        check("path 不含问号", "/v1/x".equals(imp2.path));

        // ---------------------------------------------- 只有参数表、url 是裸路径（模拟旧数据）
        Endpoint bare = new Endpoint("GET", "https", "h5.aep.com.cn", 443, "/api/list",
                "https://h5.aep.com.cn/api/list", "历史文件",
                List.<String[]>of(new String[]{"id", "10086"}, new String[]{"kw", "a b"}),
                new ArrayList<>(), "", "", "", "", 200, 0);
        check("url 缺 query 时构造器自动补", bare.url.endsWith("/api/list?id=10086&kw=a%20b"));
        check("兜底后的请求行也带 query", firstLine(bare.rawRequestBytes())
                .equals("GET /api/list?id=10086&kw=a%20b HTTP/1.1"));

        // ---------------------------------------------- 编码函数本身
        check("queryEncode 空格", "a%20b".equals(Urls.queryEncode("a b")));
        check("queryEncode 加号", "a%2Bb".equals(Urls.queryEncode("a+b")));
        check("queryEncode 中文", "%E4%B8%AD".equals(Urls.queryEncode("中")));
        check("queryEncode 保留 unreserved", "aZ0-_.~".equals(Urls.queryEncode("aZ0-_.~")));
        check("joinQuery 空列表", "".equals(Urls.joinQuery(new ArrayList<>())));
        check("joinQuery 空值只写 key", "flag".equals(Urls.joinQuery(
                List.<String[]>of(new String[]{"flag", ""}))));

        System.out.println(failed == 0 ? "URL PASS" : "URL FAILED: " + failed);
        if (failed > 0) {
            System.exit(1);
        }
    }

    static void same(String name, String url, String expectedFirstLine) {
        Endpoint ep = new Endpoint("GET", "https", "h5.aep.com.cn", 443, Urls.path(url), url, "Proxy",
                Urls.queryPairs(Urls.query(url)), new ArrayList<>(), "", "", "", "", 200, 1);
        String line = firstLine(ep.rawRequestBytes());
        if (!line.equals(expectedFirstLine)) {
            System.out.println("   期望: " + expectedFirstLine + "\n   实际: " + line);
        }
        check(name, line.equals(expectedFirstLine));
    }

    static String firstLine(byte[] bytes) {
        String s = new String(bytes, StandardCharsets.UTF_8);
        int i = s.indexOf("\r\n");
        return i < 0 ? s : s.substring(0, i);
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
