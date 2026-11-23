package yuc;

import burp.api.montoya.MontoyaApi;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * 全局请求头配置：粘一份报文进来，还原到 Repeater 时整组套用。
 * <p>
 * 为什么需要它：SQLite 里<b>不存请求头</b>（token / Cookie 天天变，存下来也是过期的）。
 * 与其每个包手改 Authorization，不如在这里配一次，所有还原出来的请求都带上。
 * <p>
 * 输入容忍三种形态，因为人从不同地方复制：
 * <ol>
 *   <li>完整的请求报文（第一行 {@code GET /x HTTP/1.1}）—— 从 Repeater 直接 Ctrl+A 复制</li>
 *   <li>完整的响应报文（第一行 {@code HTTP/1.1 200 OK}）</li>
 *   <li>光秃秃的 {@code Key: Value} 若干行</li>
 * </ol>
 * 头之后的 body 会被忽略（遇到第一个空行就停），所以直接粘整个请求也不会把 JSON 当头部。
 */
public final class HeaderProfile {

    private static final String PREF = "yuc.headers";

    /** 这些头由还原逻辑自己算，配置里写了也不会生效（留在这儿只为一眼看懂规则）。 */
    private static final Set<String> IGNORED = Set.of(
            "host", "content-length", "transfer-encoding", "connection", "proxy-connection", "expect");

    private final MontoyaApi api;
    private String raw = "";
    private List<String[]> parsed = new ArrayList<>();

    public HeaderProfile(MontoyaApi api) {
        this.api = api;
        try {
            String v = api.persistence().preferences().getString(PREF);
            this.raw = v == null ? "" : v;
        } catch (RuntimeException ignored) {
            this.raw = "";
        }
        this.parsed = parse(raw);
    }

    /** 原始文本（对话框里回显用）。 */
    public String raw() {
        return raw;
    }

    /** 解析结果；空表示没配置，还原时退回样本自己抓到的头。 */
    public List<String[]> headers() {
        return parsed;
    }

    public boolean isEmpty() {
        return parsed.isEmpty();
    }

    /** 保存并立刻生效。 */
    public void save(String text) {
        this.raw = text == null ? "" : text;
        this.parsed = parse(this.raw);
        try {
            api.persistence().preferences().setString(PREF, this.raw);
        } catch (RuntimeException ignored) {
            // 临时工程模式下没有项目持久化，忽略
        }
    }

    // ------------------------------------------------------------ 解析

    /**
     * 把任意粘贴文本解析成请求头。
     * <p>
     * 规则：跳过起始请求行/状态行（含 {@code " HTTP/"} 或以 {@code HTTP/} 开头），
     * 逐行取 {@code 名字: 值}，遇到空行即停（后面是 body），折行续行直接忽略。
     */
    public static List<String[]> parse(String text) {
        List<String[]> out = new ArrayList<>();
        if (text == null || text.isEmpty()) {
            return out;
        }
        String[] lines = text.replace("\r\n", "\n").replace('\r', '\n').split("\n", -1);

        int i = 0;
        while (i < lines.length && lines[i].trim().isEmpty()) {
            i++; // 开头的空行
        }
        if (i < lines.length && (lines[i].contains(" HTTP/") || lines[i].trim().startsWith("HTTP/"))) {
            i++; // 请求行 / 状态行
        }

        for (; i < lines.length; i++) {
            String line = lines[i];
            if (line.trim().isEmpty()) {
                break; // 头结束，后面是 body
            }
            if (line.charAt(0) == ' ' || line.charAt(0) == '\t') {
                continue; // obs-fold 续行，忽略
            }
            int colon = line.indexOf(':');
            if (colon <= 0) {
                continue;
            }
            String name = line.substring(0, colon).trim();
            if (!isToken(name) || IGNORED.contains(name.toLowerCase())) {
                continue;
            }
            out.add(new String[]{name, line.substring(colon + 1).trim()});
        }
        return out;
    }

    /** 头名字只能是 token（RFC 7230），防止把 JSON 里的 {@code "key": 1} 当成头。 */
    private static boolean isToken(String name) {
        if (name.isEmpty() || name.length() > 64) {
            return false;
        }
        for (int i = 0; i < name.length(); i++) {
            char c = name.charAt(i);
            boolean ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
                    || c == '-' || c == '_' || c == '.' || c == '!' || c == '*' || c == '+' || c == '\'';
            if (!ok) {
                return false;
            }
        }
        return true;
    }

    /** 对话框里的「识别结果」：几条生效、几条被忽略，让人一眼确认粘对了。 */
    public static String describe(String text) {
        List<String[]> hs = parse(text);
        if (hs.isEmpty()) {
            return "没有识别到请求头 — 直接写 Key: Value 一行一个，或整段粘贴 Repeater 报文";
        }
        StringBuilder sb = new StringBuilder("识别到 ").append(hs.size()).append(" 条：");
        for (int i = 0; i < hs.size() && i < 6; i++) {
            sb.append(i == 0 ? " " : "、").append(hs.get(i)[0]);
        }
        if (hs.size() > 6) {
            sb.append(" 等");
        }
        sb.append("（Host / Content-Length 由插件重算，不需要写）");
        return sb.toString();
    }
}
