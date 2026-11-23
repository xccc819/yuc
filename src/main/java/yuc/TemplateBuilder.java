package yuc;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 把一批 {@link Endpoint} 写成 v3-lite 模板（base + items + 扁平参数表）。
 * <p>
 * 一个域名端口一个文件，文件里就是「这个站的后端接口清单」，可以直接喂给
 * check_v3lite.py 还原成真实报文。
 */
public final class TemplateBuilder {

    private TemplateBuilder() {
    }

    public static Map<String, Object> domainDoc(String scheme, String host, int port, List<Endpoint> endpoints) {
        Map<String, Object> base = new LinkedHashMap<>();
        base.put("scheme", scheme);
        base.put("host", host);
        base.put("port", port);
        // 整站共用的鉴权头只写一次：一百个接口各记一遍 Cookie 是纯浪费
        Map<String, String> headers = HeaderPolicy.collect(endpoints);
        if (!headers.isEmpty()) {
            base.put("headers", headers);
        }

        List<Endpoint> sorted = new ArrayList<>(endpoints);
        sorted.sort((a, b) -> {
            int c = a.path.compareTo(b.path);
            return c != 0 ? c : a.method.compareTo(b.method);
        });

        List<Object> items = new ArrayList<>();
        Set<String> usedIds = new HashSet<>();
        Set<String> skipCookies = baseCookies(headers);
        for (Endpoint ep : sorted) {
            items.add(item(ep, usedIds, skipCookies));
        }

        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("base", base);
        doc.put("items", items);
        return doc;
    }

    public static Map<String, Object> item(Endpoint ep, Set<String> usedIds) {
        return item(ep, usedIds, Set.of());
    }

    /**
     * @param skipCookies 已经进了 {@code base.headers} 的 Cookie 键，逐条不再重复
     */
    public static Map<String, Object> item(Endpoint ep, Set<String> usedIds, Set<String> skipCookies) {
        Map<String, Object> item = new LinkedHashMap<>();
        item.put("id", uniqueId(ep, usedIds));
        item.put("name", ep.method + " " + ep.path);
        item.put("method", ep.method);
        item.put("uri", ep.path);

        List<Map<String, Object>> params = Params.templateParams(ep, skipCookies);
        if (!params.isEmpty()) {
            item.put("params", params);
        }
        return item;
    }

    /** base.headers 里的 Cookie 拆成 {@code name\u0000value} 集合，用于去重。 */
    static Set<String> baseCookies(Map<String, String> baseHeaders) {
        Set<String> out = new HashSet<>();
        if (baseHeaders == null) {
            return out;
        }
        for (Map.Entry<String, String> e : baseHeaders.entrySet()) {
            if (!"cookie".equalsIgnoreCase(e.getKey())) {
                continue;
            }
            for (String[] p : Urls.cookiePairs(e.getValue())) {
                out.add(p[0] + '\u0000' + p[1]);
            }
        }
        return out;
    }

    private static String uniqueId(Endpoint ep, Set<String> used) {
        String raw = (ep.method + "-" + ep.path).toLowerCase();
        String slug = raw.replaceAll("[^a-z0-9]+", "-").replaceAll("(^-+)|(-+$)", "");
        if (slug.isEmpty()) {
            slug = "item";
        }
        if (slug.length() > 60) {
            slug = slug.substring(0, 60).replaceAll("-+$", "");
        }
        String id = slug;
        int n = 2;
        while (!used.add(id)) {
            id = slug + "-" + n++;
        }
        return id;
    }

    /** 文件名：域名_端口.json（域名里的非法字符换成下划线）。 */
    public static String fileName(String host, int port) {
        return Urls.safeFileName(host) + "_" + port + ".json";
    }
}
