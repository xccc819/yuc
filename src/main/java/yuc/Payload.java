package yuc;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 把选中的参数拼成能直接粘进请求的一段 payload。
 * <p>
 * 三种格式对应三处测试场景，取值原则不一样：
 * <ul>
 *   <li><b>raw</b>（{@code a=1&b=2}）—— 值<b>原样输出、不做百分号编码</b>。样本里的值本来就是解码后的，
 *       打 SQL 注入 / XSS 时要能直接改成 {@code 1' or '1'='1}，编一遍就废了。</li>
 *   <li><b>json</b>（{@code {"a":"1"}}）—— 值一律当字符串，保证结果永远是合法 JSON；
 *       键名按 Java 字符串转义，中文不转义（读得懂）。</li>
 *   <li><b>xml</b>（{@code <a>1</a>}）—— 键名合法就当标签名，不合法（{@code data.list[].id}
 *       这种）退化成 {@code <param name="…">}，值做实体转义。</li>
 * </ul>
 * 参数顺序就是界面上看到的顺序，方便对照。
 */
public final class Payload {

    private Payload() {
    }

    /** a=1&b=2：值不转义，只把空名跳过。 */
    public static String raw(List<String[]> pairs) {
        StringBuilder sb = new StringBuilder();
        for (String[] p : pairs) {
            if (p == null || p[0] == null || p[0].isEmpty()) {
                continue;
            }
            if (sb.length() > 0) {
                sb.append('&');
            }
            sb.append(p[0]).append('=').append(nullToEmpty(p[1]));
        }
        return sb.toString();
    }

    /** {"a":"1","b":"2"}：单行紧凑输出，粘进 body 不用先删换行。 */
    public static String json(List<String[]> pairs) {
        Map<String, Object> map = new LinkedHashMap<>();
        for (String[] p : pairs) {
            if (p == null || p[0] == null || p[0].isEmpty()) {
                continue;
            }
            map.put(p[0], nullToEmpty(p[1]));
        }
        return MiniJson.write(map);
    }

    /** XML：首行声明 + {@code <request>} 根节点，元素名不合法时退化成 param name="…"。 */
    public static String xml(List<String[]> pairs) {
        StringBuilder sb = new StringBuilder("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<request>");
        for (String[] p : pairs) {
            if (p == null || p[0] == null || p[0].isEmpty()) {
                continue;
            }
            String name = p[0];
            String value = escapeXml(nullToEmpty(p[1]));
            sb.append("\n  ");
            if (nameOk(name)) {
                sb.append('<').append(name).append('>')
                        .append(value)
                        .append("</").append(name).append('>');
            } else {
                sb.append("<param name=\"").append(escapeXml(name)).append("\">")
                        .append(value)
                        .append("</param>");
            }
        }
        sb.append("\n</request>\n");
        return sb.toString();
    }

    /** 能不能直接拿来做标签名：字母/下划线开头，后面是字母数字 {@code . - _}；不能叫 xml 开头。 */
    public static boolean nameOk(String name) {
        if (name == null || name.isEmpty()) {
            return false;
        }
        if (name.length() >= 3 && name.regionMatches(true, 0, "xml", 0, 3)) {
            return false; // XML 规范保留
        }
        char first = name.charAt(0);
        if (!(Character.isLetter(first) || first == '_')) {
            return false;
        }
        for (int i = 0; i < name.length(); i++) {
            char c = name.charAt(i);
            if (!(Character.isLetterOrDigit(c) || c == '_' || c == '-' || c == '.')) {
                return false;
            }
        }
        return true;
    }

    static String escapeXml(String s) {
        StringBuilder sb = new StringBuilder(s.length() + 8);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '&': sb.append("&amp;"); break;
                case '<': sb.append("&lt;"); break;
                case '>': sb.append("&gt;"); break;
                case '"': sb.append("&quot;"); break;
                case '\'': sb.append("&apos;"); break;
                default: sb.append(c);
            }
        }
        return sb.toString();
    }

    private static String nullToEmpty(String s) {
        return s == null ? "" : s;
    }
}
