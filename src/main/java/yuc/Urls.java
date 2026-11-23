package yuc;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/** URL 的拆解与路径规则。全部手写，不用 java.net.URI（Burp 里的 URL 常带空格、花括号，URI 会抛异常）。 */
public final class Urls {

    private Urls() {
    }

    /** 去掉 scheme://authority 之后的路径部分（不含 ? 与 #）。 */
    public static String path(String url) {
        if (url == null) {
            return "/";
        }
        int from = 0;
        int schemeEnd = url.indexOf("://");
        if (schemeEnd >= 0) {
            int slash = url.indexOf('/', schemeEnd + 3);
            from = slash >= 0 ? slash : url.length();
        }
        int q = url.indexOf('?', from);
        int h = url.indexOf('#', from);
        int end = url.length();
        if (q >= 0) {
            end = Math.min(end, q);
        }
        if (h >= 0) {
            end = Math.min(end, h);
        }
        String p = url.substring(from, end);
        return p.isEmpty() ? "/" : p;
    }

    /** ? 之后、# 之前的部分，没有则空串。 */
    public static String query(String url) {
        if (url == null) {
            return "";
        }
        int q = url.indexOf('?');
        if (q < 0) {
            return "";
        }
        int h = url.indexOf('#', q);
        return h < 0 ? url.substring(q + 1) : url.substring(q + 1, h);
    }

    /** a=1&b=2 → [[a,1],[b,2]]，名字与值都做百分号解码；只有名字的裸参数值记为空串。 */
    public static List<String[]> queryPairs(String query) {
        List<String[]> out = new ArrayList<>();
        if (query == null || query.isEmpty()) {
            return out;
        }
        for (String piece : query.split("&")) {
            if (piece.isEmpty()) {
                continue;
            }
            int eq = piece.indexOf('=');
            String name = eq < 0 ? piece : piece.substring(0, eq);
            String value = eq < 0 ? "" : piece.substring(eq + 1);
            out.add(new String[]{pctDecode(name), pctDecode(value)});
        }
        return out;
    }

    /**
     * 表单体（application/x-www-form-urlencoded）解析：这里的 + 就是空格，
     * 和 query 里的 + 不是一回事——表单必须按 plus=space 解，否则 a+b 会被当成字面加号，
     * 重新编码时变成 %2B，报文就变了。
     */
    public static List<String[]> formPairs(String body) {
        List<String[]> out = new ArrayList<>();
        if (body == null || body.isEmpty()) {
            return out;
        }
        for (String piece : body.split("&")) {
            if (piece.isEmpty()) {
                continue;
            }
            int eq = piece.indexOf('=');
            String name = eq < 0 ? piece : piece.substring(0, eq);
            String value = eq < 0 ? "" : piece.substring(eq + 1);
            out.add(new String[]{formDecode(name), formDecode(value)});
        }
        return out;
    }

    private static String formDecode(String s) {
        return pctDecode(s.replace('+', ' '));
    }

    /** Cookie 头 → [[name,value],...] */
    public static List<String[]> cookiePairs(String cookieHeader) {
        List<String[]> out = new ArrayList<>();
        if (cookieHeader == null || cookieHeader.isBlank()) {
            return out;
        }
        for (String piece : cookieHeader.split(";")) {
            String p = piece.trim();
            if (p.isEmpty()) {
                continue;
            }
            int eq = p.indexOf('=');
            out.add(eq < 0 ? new String[]{p, ""} : new String[]{p.substring(0, eq).trim(), p.substring(eq + 1).trim()});
        }
        return out;
    }

    /** 路径按 / 切开，丢掉空段。 */
    public static List<String> segments(String path) {
        List<String> out = new ArrayList<>();
        if (path == null) {
            return out;
        }
        for (String s : path.split("/")) {
            if (!s.isEmpty()) {
                out.add(s);
            }
        }
        return out;
    }

    /** 最后一段（末尾有 / 也能拿到有内容的那段）。 */
    public static String lastSegment(String path) {
        List<String> segs = segments(path);
        return segs.isEmpty() ? "" : segs.get(segs.size() - 1);
    }

    public static String firstSegment(String path) {
        List<String> segs = segments(path);
        return segs.isEmpty() ? "" : segs.get(0);
    }

    /**
     * 判断这是不是「后端接口」。
     * <p>
     * 规则只有一条：末段不能含点号。`/static/app.js`、`/v1/user.json`、`/img/logo.png?v=1`
     * 这类全是前端静态资源，一律不算接口；末段为空（就是 /）也不算。
     */
    public static boolean looksLikeApi(String path) {
        String last = lastSegment(path);
        return !last.isEmpty() && last.indexOf('.') < 0;
    }

    /** %XX 解码（UTF-8），不把 + 当空格——URL 路径里的 + 就是加号。 */
    public static String pctDecode(String s) {
        if (s == null || s.indexOf('%') < 0) {
            return s == null ? "" : s;
        }
        ByteArrayOutputStream buf = new ByteArrayOutputStream(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '%' && i + 2 < s.length()) {
                int hi = Character.digit(s.charAt(i + 1), 16);
                int lo = Character.digit(s.charAt(i + 2), 16);
                if (hi >= 0 && lo >= 0) {
                    buf.write((hi << 4) + lo);
                    i += 2;
                    continue;
                }
            }
            byte[] bytes = String.valueOf(c).getBytes(StandardCharsets.UTF_8);
            buf.write(bytes, 0, bytes.length);
        }
        return buf.toString(StandardCharsets.UTF_8);
    }

    /** 路径展示模式：完整 / 只要左边 N 段 / 只要右边 N 段。 */
    public static final int PATH_FULL = 0;
    public static final int PATH_LEFT = 1;
    public static final int PATH_RIGHT = 2;

    /**
     * 按段数截断路径，只影响"显示"，不影响存储和还原。
     * <p>
     * `/aaa/bbb/ccc` + 左 2 → `/aaa/bbb`；+ 右 2 → `/bbb/ccc`。
     */
    public static String displayPath(String path, int mode, int depth) {
        List<String> segs = segments(path);
        if (mode == PATH_FULL || depth <= 0 || segs.size() <= depth) {
            return path;
        }
        List<String> sub = mode == PATH_LEFT
                ? segs.subList(0, depth)
                : segs.subList(segs.size() - depth, segs.size());
        return "/" + String.join("/", sub);
    }

    /** 文件名安全化：\ / : * ? " < > | 全部换成下划线。 */
    public static String safeFileName(String s) {
        return s.replaceAll("[\\\\/:*?\"<>|]", "_");
    }

    /** 表单编码：空格写成 {@code +}，与 {@link #formPairs} 的解码方式对称。 */
    public static String formEncode(String s) {
        try {
            return java.net.URLEncoder.encode(s == null ? "" : s, "UTF-8");
        } catch (java.io.UnsupportedEncodingException e) {
            return s == null ? "" : s;
        }
    }

    /**
     * query 编码：空格写成 {@code %20}（**不是 {@code +}**）。
     * <p>
     * query 里的 {@code +} 是字面加号，所以编码时也不能把它当空格；
     * 用 {@link #formEncode} 会把空格变 {@code +}，对那些把 {@code +} 当字面加号的后端就是错的。
     */
    public static String queryEncode(String s) {
        if (s == null || s.isEmpty()) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        for (byte raw : s.getBytes(StandardCharsets.UTF_8)) {
            int b = raw & 0xFF;
            char c = (char) b;
            boolean plain = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
                    || c == '-' || c == '_' || c == '.' || c == '~';
            if (plain) {
                sb.append(c);
            } else {
                sb.append('%').append(Character.toUpperCase(Character.forDigit(b >> 4, 16)))
                        .append(Character.toUpperCase(Character.forDigit(b & 0xF, 16)));
            }
        }
        return sb.toString();
    }

    /** [[k,v],…] → {@code k=v&k2=v2}（用于「只有解码后的参数表、没有原始 query 串」时重建）。 */
    public static String joinQuery(List<String[]> pairs) {
        if (pairs == null || pairs.isEmpty()) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        for (String[] p : pairs) {
            if (p == null || p[0] == null || p[0].isEmpty()) {
                continue;
            }
            if (sb.length() > 0) {
                sb.append('&');
            }
            sb.append(queryEncode(p[0]));
            if (p.length > 1 && p[1] != null && !p[1].isEmpty()) {
                sb.append('=').append(queryEncode(p[1]));
            }
        }
        return sb.toString();
    }

    /** 这些是「公共后缀」，取根域时得多带一段：api.aep.com.cn → aep.com.cn 而不是 com.cn。 */
    private static final java.util.Set<String> SECOND_LEVEL = java.util.Set.of(
            "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn",
            "com.hk", "com.tw", "com.mo", "com.sg", "com.au", "com.br", "com.tr", "com.ru",
            "co.uk", "org.uk", "ac.uk", "co.jp", "ne.jp", "co.kr", "co.nz", "co.in");

    /**
     * 取根域名，用来给左侧树分组：
     * {@code h5.aep.com.cn → aep.com.cn}，{@code api.example.co.uk → example.co.uk}。
     * <p>
     * IP 走另一套：{@code 192.168.1.37 → 192.168.1.0/24}。一次测试里内网往往是一整段
     * （10.0.0.5 / 10.0.0.6 / 10.0.0.9…），按域名那套切出来是 {@code 1.37} 这种鬼东西，
     * 而且每台机器各占一组，等于没分组。
     */
    public static String rootDomain(String host) {
        if (host == null || host.isEmpty()) {
            return "";
        }
        if (host.indexOf(':') >= 0) {
            return host; // IPv6 不做聚合，原样当一组
        }
        String h = host.toLowerCase();
        if (isIpv4(h)) {
            return ipv4Prefix24(h);
        }
        String[] p = h.split("\\.");
        if (p.length <= 2) {
            return h;
        }
        String last2 = p[p.length - 2] + "." + p[p.length - 1];
        if (SECOND_LEVEL.contains(last2) && p.length >= 3) {
            return p[p.length - 3] + "." + last2;
        }
        return last2;
    }

    /**
     * 是不是标准点分十进制 IPv4（四段、每段 0-255、不认前导 {@code +}/{@code -}）。
     * <p>
     * 故意不认 {@code 0x7f.1} / {@code 127.1} 这类简写：Burp 交上来的 host 基本都是规范的，
     * 放宽反而会把 {@code 1.2.3.4.5} 这种真域名误判成 IP。
     */
    public static boolean isIpv4(String host) {
        if (host == null) {
            return false;
        }
        String[] p = host.split("\\.", -1);
        if (p.length != 4) {
            return false;
        }
        for (String seg : p) {
            if (seg.isEmpty() || seg.length() > 3) {
                return false;
            }
            for (int i = 0; i < seg.length(); i++) {
                if (!Character.isDigit(seg.charAt(i))) {
                    return false;
                }
            }
            if (Integer.parseInt(seg) > 255) {
                return false;
            }
        }
        return true;
    }

    /** {@code 10.2.3.4 → 10.2.3.0/24}；不是 IPv4 就返回 {@code ""}。 */
    public static String ipv4Prefix24(String host) {
        if (!isIpv4(host)) {
            return "";
        }
        String[] p = host.split("\\.");
        return p[0] + "." + p[1] + "." + p[2] + ".0/24";
    }
}
