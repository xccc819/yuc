import yuc.Payload;

import java.util.ArrayList;
import java.util.List;

/**
 * 「复制为 payload」三种格式的离线自测：格式对不对、转义够不够、退化分支走没走。
 */
public class PayloadSmoke {

    static int failed = 0;

    public static void main(String[] args) {
        List<String[]> pairs = new ArrayList<>();
        pairs.add(new String[]{"page", "1"});
        pairs.add(new String[]{"keyword", "张三"});
        pairs.add(new String[]{"empty", ""});
        pairs.add(new String[]{"", "丢弃"});

        // ---------------------------------------------------------------- raw
        String raw = Payload.raw(pairs);
        check("raw 用 & 拼接且跳过空名", "page=1&keyword=张三&empty=".equals(raw));

        List<String[]> inject = List.<String[]>of(new String[]{"id", "1' or '1'='1"});
        check("raw 不转义引号（渗透要能直接改）", "id=1' or '1'='1".equals(Payload.raw(inject)));
        check("raw 不转义 & 与 %",
                "q=a&b".equals(Payload.raw(List.<String[]>of(new String[]{"q", "a&b"})))
                        && "q=a%20b".equals(Payload.raw(List.<String[]>of(new String[]{"q", "a%20b"}))));
        check("raw 空列表 → 空串", Payload.raw(List.of()).isEmpty());
        check("raw 值为 null 当空串", "a=".equals(Payload.raw(List.<String[]>of(new String[]{"a", null}))));

        // --------------------------------------------------------------- json
        String json = Payload.json(pairs);
        check("json 紧凑单行、值都是字符串", "{\"page\":\"1\",\"keyword\":\"张三\",\"empty\":\"\"}".equals(json));
        check("json 中文不转义", json.contains("张三"));
        check("json 空列表 → {}", "{}".equals(Payload.json(List.of())));

        String tricky = Payload.json(List.<String[]>of(new String[]{"a\"b", "c\\d\ne"}));
        check("json 转义引号/反斜杠/换行", "{\"a\\\"b\":\"c\\\\d\\ne\"}".equals(tricky));
        check("json 结果能被自己解析回来", parseOk(tricky));

        // ---------------------------------------------------------------- xml
        String xml = Payload.xml(List.<String[]>of(new String[]{"a", "1"}, new String[]{"b", "2"}));
        check("xml 带声明 + request 根节点",
                xml.startsWith("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<request>")
                        && xml.endsWith("</request>\n"));
        check("xml 每行一个元素",
                xml.contains("\n  <a>1</a>") && xml.contains("\n  <b>2</b>"));

        String esc = Payload.xml(List.<String[]>of(new String[]{"q", "<a>&\"'"}));
        check("xml 值做实体转义", esc.contains("&lt;a&gt;&amp;&quot;&apos;"));

        String dotted = Payload.xml(List.<String[]>of(new String[]{"data.list[].id", "7"}));
        check("非法标签名退化成 param name", dotted.contains("<param name=\"data.list[].id\">7</param>"));

        String chinese = Payload.xml(List.<String[]>of(new String[]{"用户名", "张三"}));
        check("中文键名可作标签名", chinese.contains("<用户名>张三</用户名>"));

        String reserved = Payload.xml(List.<String[]>of(new String[]{"xmlData", "1"}));
        check("xml 前缀的键名退化（XML 保留）", reserved.contains("<param name=\"xmlData\">1</param>"));

        check("xml 空列表只有根节点",
                Payload.xml(List.of()).contains("<request>\n</request>"));

        check("nameOk 边界",
                Payload.nameOk("a-b_c.d") && !Payload.nameOk("1a") && !Payload.nameOk("a b"));

        System.out.println(failed == 0 ? "PAYLOAD PASS" : "PAYLOAD FAILED: " + failed);
        if (failed > 0) {
            System.exit(1);
        }
    }

    static boolean parseOk(String json) {
        try {
            Object v = yuc.MiniJson.parse(json);
            return v instanceof java.util.Map;
        } catch (RuntimeException e) {
            return false;
        }
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
