package yuc;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;

/**
 * 采集范围与响应大小的设置。
 * <p>
 * 两个维度，各自独立：
 * <ul>
 *   <li><b>收录范围</b>：黑名单命中就丢；白名单非空时"只收命中的"。名单里的每条是一个
 *       glob（{@code *} 匹配任意串、{@code ?} 匹配单字符）：
 *       以 {@code /} 开头的匹配<b>路径</b>（{@code /api/admin*}），否则匹配 <b>host</b>
 *       （{@code *google.*}）。</li>
 *   <li><b>响应范围</b>：正文超过 {@code maxParseBytes} 只记长度不解析；
 *       每个接口最多记 {@code maxResponseFields} 个响应字段（0 = 不限）。这两项直接决定
 *       库和内存的大小——响应字段是这类库里的行数大头。</li>
 * </ul>
 * 默认黑名单放的是"测了也没用、还特别占地方"的站点（搜索引擎、代码托管、空间测绘、
 * 广告拦截规则站、以及 gov/edu 这类通常不在授权范围的域）。
 * <p>
 * 持久化写进 {@code yuc.db} 的 {@code settings} 表（{@code yuc.rules.*} / {@code yuc.limit.*}），
 * <b>跟库走</b>：换机器只拷 {@code yuc.db} 就能把采集策略一起带走，而不是绑在 Burp 的工程文件上。
 */
public final class Settings {

    /** 偏好读写的最小接口；Burp 里包一层 preferences，自测里用 HashMap 就行。 */
    public interface Prefs {
        String get(String key);

        void set(String key, String value);
    }

    public static final String[] DEFAULT_BLACKLIST = {
            "*google.*",
            "*github.*",
            "*shodan.io",
            "*fofa.info",
            "*adblockplus.org",
            "*bing.com",
            "*gov.cn",
            "*edu.cn",
    };

    public static final long DEFAULT_MAX_PARSE = 4L * 1024 * 1024;
    public static final int DEFAULT_MAX_FIELDS = 500;

    private static final String K_BLACK = "yuc.rules.blacklist";
    private static final String K_WHITE = "yuc.rules.whitelist";
    private static final String K_PARSE = "yuc.limit.maxParse";
    private static final String K_FIELDS = "yuc.limit.maxFields";

    private final Prefs prefs;

    /** 原始文本（一行一条），界面上直接编辑它。 */
    private volatile String blacklistText = "";
    private volatile String whitelistText = "";
    private volatile long maxParseBytes = DEFAULT_MAX_PARSE;
    private volatile int maxResponseFields = DEFAULT_MAX_FIELDS;

    /** 编译好的规则缓存，改文本时重建。 */
    private volatile List<Rule> blacklist = List.of();
    private volatile List<Rule> whitelist = List.of();

    /** 一条规则：原始 glob + 编译结果 + 匹配目标（路径 or host）。 */
    static final class Rule {
        final String glob;
        final Pattern pattern;
        final boolean onPath;

        Rule(String glob, boolean onPath) {
            this.glob = glob;
            this.onPath = onPath;
            this.pattern = glob(glob);
        }
    }

    public Settings(Prefs prefs) {
        this.prefs = prefs;
        load();
    }

    /** 不带持久化的默认设置（自测、以及没有工程文件时兜底）。 */
    public static Settings defaults() {
        return new Settings(null);
    }

    // ------------------------------------------------------------ 读写

    private void load() {
        String black = read(K_BLACK);
        // 第一次运行：黑名单预置这 8 条；用户清空后存的是空串，不会又冒出来
        blacklistText = black == null ? String.join("\n", DEFAULT_BLACKLIST) : black;
        String white = read(K_WHITE);
        whitelistText = white == null ? "" : white;
        maxParseBytes = clampParse(parseLong(read(K_PARSE), DEFAULT_MAX_PARSE));
        maxResponseFields = clampFields((int) parseLong(read(K_FIELDS), DEFAULT_MAX_FIELDS));
        recompile();
    }

    /** 重新从存储读一遍（打开/切换数据库之后调用）。 */
    public void reload() {
        load();
    }

    public void save() {
        if (prefs == null) {
            return;
        }
        prefs.set(K_BLACK, blacklistText);
        prefs.set(K_WHITE, whitelistText);
        prefs.set(K_PARSE, String.valueOf(maxParseBytes));
        prefs.set(K_FIELDS, String.valueOf(maxResponseFields));
    }

    private String read(String key) {
        try {
            return prefs == null ? null : prefs.get(key);
        } catch (RuntimeException e) {
            return null;
        }
    }

    private static long parseLong(String raw, long fallback) {
        try {
            return raw == null || raw.isEmpty() ? fallback : Long.parseLong(raw.trim());
        } catch (NumberFormatException e) {
            return fallback;
        }
    }

    private static long clampParse(long v) {
        long lo = 64 * 1024L;
        long hi = 256L * 1024 * 1024;
        return Math.max(lo, Math.min(hi, v));
    }

    private static int clampFields(int v) {
        return Math.max(0, Math.min(50000, v));
    }

    // ------------------------------------------------------------ 收录范围

    public String blacklistText() {
        return blacklistText;
    }

    public String whitelistText() {
        return whitelistText;
    }

    public void setRules(String blacklistText, String whitelistText) {
        this.blacklistText = blacklistText == null ? "" : blacklistText;
        this.whitelistText = whitelistText == null ? "" : whitelistText;
        recompile();
    }

    public void resetBlacklistToDefault() {
        setRules(String.join("\n", DEFAULT_BLACKLIST), whitelistText);
    }

    public List<String> blacklist() {
        return lines(blacklistText);
    }

    public List<String> whitelist() {
        return lines(whitelistText);
    }

    /** 这条请求要不要收：黑名单命中 → 否；白名单非空且没命中 → 否。 */
    public boolean allows(String host, String path) {
        if (host == null) {
            host = "";
        }
        if (path == null) {
            path = "/";
        }
        if (matches(blacklist, host, path)) {
            return false;
        }
        List<Rule> white = whitelist;
        return white.isEmpty() || matches(white, host, path);
    }

    private static boolean matches(List<Rule> rules, String host, String path) {
        for (Rule r : rules) {
            if (r.pattern.matcher(r.onPath ? path : host).matches()) {
                return true;
            }
        }
        return false;
    }

    private void recompile() {
        blacklist = compile(blacklistText);
        whitelist = compile(whitelistText);
    }

    /** 文本 → 编译后的 glob 列表（忽略空行与 # 注释行）。 */
    static List<Rule> compile(String text) {
        List<Rule> out = new ArrayList<>();
        for (String line : lines(text)) {
            out.add(new Rule(line, line.startsWith("/")));
        }
        return Collections.unmodifiableList(out);
    }

    static List<String> lines(String text) {
        List<String> out = new ArrayList<>();
        if (text == null) {
            return out;
        }
        for (String raw : text.split("\\R")) {
            String line = raw.trim();
            if (!line.isEmpty() && !line.startsWith("#")) {
                out.add(line);
            }
        }
        return out;
    }

    /** glob → 正则：`*` 任意串、`?` 单字符，其余字符按字面量处理。 */
    static Pattern glob(String glob) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < glob.length(); i++) {
            char c = glob.charAt(i);
            if (c == '*') {
                sb.append(".*");
            } else if (c == '?') {
                sb.append('.');
            } else if ("\\^$.|+()[]{}".indexOf(c) >= 0) {
                sb.append('\\').append(c);
            } else {
                sb.append(c);
            }
        }
        return Pattern.compile(sb.toString(), Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE);
    }

    // ------------------------------------------------------------ 响应范围

    public long maxParseBytes() {
        return maxParseBytes;
    }

    public void setMaxParseBytes(long value) {
        maxParseBytes = clampParse(value);
    }

    public int maxResponseFields() {
        return maxResponseFields;
    }

    public void setMaxResponseFields(int value) {
        maxResponseFields = clampFields(value);
    }

    /** 给界面看的一句话摘要。 */
    public String summary() {
        int black = blacklist().size();
        int white = whitelist().size();
        String scope = white > 0 ? ("白名单 " + white + " 条") : ("黑名单 " + black + " 条");
        return "范围 " + scope + " · 解析上限 " + (maxParseBytes / (1024 * 1024)) + " MB · 字段上限 "
                + (maxResponseFields == 0 ? "不限" : maxResponseFields + " 个/接口");
    }
}
