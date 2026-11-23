package yuc;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 哪些请求头该进模板的 {@code base.headers}。
 * <p>
 * 起因很实际：一个站一百个接口，每个接口都把同一份 {@code Cookie} / {@code Authorization}
 * 记一遍，模板里九成内容都是重复的。这些头整站共用，记一次放 base 就够。
 * <p>
 * 但不是什么头都能进 base：
 * <ul>
 *   <li><b>缓存与条件请求</b>（{@code Cache-Control} / {@code If-None-Match} / {@code If-Modified-Since} …）
 *       天天变，写进 base 会让模板失效，而且会把参数统计搅乱——所以一律不要</li>
 *   <li><b>内容协商与浏览器指纹</b>（{@code Accept*} / {@code User-Agent} / {@code Sec-Fetch-*} …）
 *       不是鉴权信息，留着只会让 base 变成大杂烩</li>
 *   <li><b>由程序重算的</b>（{@code Host} / {@code Content-Length} / {@code Transfer-Encoding} …）
 *       写了也会被覆盖</li>
 * </ul>
 * 剩下的、且命中鉴权关键词的（cookie / authorization / token / api-key / csrf / session …）才进 base。
 */
public final class HeaderPolicy {

    /** 绝不能进 base：缓存、条件请求、传输、内容协商、浏览器指纹。 */
    private static final Set<String> NEVER = Set.of(
            // 传输/分帧，由程序重算
            "host", "content-length", "transfer-encoding", "connection", "proxy-connection", "expect",
            "keep-alive", "te", "trailer", "upgrade", "via",
            // body 描述，每个接口不同
            "content-type", "content-encoding", "content-language", "content-location",
            // 缓存与条件请求 —— 用户明确要求排除
            "cache-control", "pragma", "expires", "age", "etag", "last-modified", "vary", "date",
            "if-none-match", "if-modified-since", "if-match", "if-unmodified-since", "if-range",
            "range", "warning", "x-cache", "x-cache-lookup", "cdn-cache-control", "surrogate-control",
            // 内容协商与浏览器指纹
            "accept", "accept-encoding", "accept-language", "accept-charset", "accept-datetime",
            "user-agent", "referer", "origin", "dnt", "upgrade-insecure-requests",
            "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest", "sec-fetch-user", "sec-purpose",
            "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "sec-ch-ua-full-version",
            "priority", "purpose");

    /** 鉴权相关关键词，命中即认为是"整站共用的身份信息"。 */
    private static final String[] AUTH_HINTS = {
            "cookie", "authorization", "auth", "token", "session", "api-key", "apikey", "api_key",
            "secret", "csrf", "xsrf", "credential", "jwt", "bearer", "sign", "access-key", "ticket"};

    private HeaderPolicy() {
    }

    /** 缓存 / 条件请求类：模板里不该出现，参数表里也不该展示（会把统计搅乱）。 */
    public static boolean isCacheHeader(String name) {
        if (name == null) {
            return false;
        }
        String n = name.toLowerCase();
        if (n.contains("cache")) {
            return true;
        }
        switch (n) {
            case "pragma":
            case "expires":
            case "age":
            case "etag":
            case "last-modified":
            case "vary":
            case "date":
            case "if-none-match":
            case "if-modified-since":
            case "if-match":
            case "if-unmodified-since":
            case "if-range":
            case "range":
                return true;
            default:
                return false;
        }
    }

    /** 该头能不能进 base.headers。 */
    public static boolean isSharedHeader(String name) {
        if (name == null || name.isEmpty()) {
            return false;
        }
        String n = name.toLowerCase();
        if (NEVER.contains(n) || isCacheHeader(n)) {
            return false;
        }
        for (String hint : AUTH_HINTS) {
            if (n.contains(hint)) {
                return true;
            }
        }
        return false;
    }

    /**
     * 从一组样本里挑出整站共用的请求头。
     * <p>
     * 取值的策略：**出现次数最多的值**（同一站点的 Cookie 会有几次刷新，占比最大的那个才是当前会话），
     * 次数一样取后出现的。头名的顺序按第一次出现的顺序，读模板时更容易对照抓包。
     */
    public static Map<String, String> collect(List<Endpoint> endpoints) {
        Map<String, String> out = new LinkedHashMap<>();
        if (endpoints == null || endpoints.isEmpty()) {
            return out;
        }
        // 头名（小写）→ { 展示名, 值 → 次数 }, 以及首次出现顺序
        Map<String, String> display = new LinkedHashMap<>();
        Map<String, Map<String, Integer>> votes = new LinkedHashMap<>();
        for (Endpoint ep : endpoints) {
            for (String[] h : ep.requestHeaders) {
                if (!isSharedHeader(h[0])) {
                    continue;
                }
                String key = h[0].toLowerCase();
                String value = h[1] == null ? "" : h[1];
                if (value.isEmpty()) {
                    continue;
                }
                display.putIfAbsent(key, h[0]);
                votes.computeIfAbsent(key, k -> new LinkedHashMap<>())
                        .merge(value, 1, Integer::sum);
            }
        }
        for (Map.Entry<String, Map<String, Integer>> e : votes.entrySet()) {
            String best = null;
            int bestCount = -1;
            for (Map.Entry<String, Integer> v : e.getValue().entrySet()) {
                if (v.getValue() >= bestCount) { // >= 让后出现的同票胜出
                    best = v.getKey();
                    bestCount = v.getValue();
                }
            }
            if (best != null) {
                out.put(display.get(e.getKey()), best);
            }
        }
        return out;
    }

    /** base.headers → 参数行（给界面用），已经排掉缓存类。 */
    public static List<String[]> asPairs(Map<String, String> headers) {
        List<String[]> out = new ArrayList<>();
        if (headers == null) {
            return out;
        }
        for (Map.Entry<String, String> e : headers.entrySet()) {
            if (isCacheHeader(e.getKey())) {
                continue;
            }
            out.add(new String[]{e.getKey(), e.getValue()});
        }
        return out;
    }
}
