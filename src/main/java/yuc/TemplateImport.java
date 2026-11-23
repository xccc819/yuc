package yuc;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 老数据迁移：把目录里已有的 {@code 域名_端口.json}（v3-lite 模板）读回内存。
 * <p>
 * 为什么必须有它：从「内存 + JSON」升级到「内存 + SQLite + JSON」时，新库是空的，
 * 内存也是空的。如果一个接口都不恢复，下一次落盘就会把这个域名**整文件覆盖**成
 * 只有新抓那一条——磁盘上攒了半天的资产瞬间没了。
 * <p>
 * 迁移是只读的：只解析、不改原文件；真正写盘仍然走 {@link TemplateBuilder}。
 * 模板里没有响应字段（v3-lite 只描述请求），所以恢复出来的样本「响应」分类是空的。
 */
public final class TemplateImport {

    private TemplateImport() {
    }

    /** 扫目录顶层的 *.json（不进子目录，避免把备份目录又导入一遍）。 */
    public static List<Endpoint> loadDir(File dir) {
        List<Endpoint> out = new ArrayList<>();
        if (dir == null || !dir.isDirectory()) {
            return out;
        }
        File[] files = dir.listFiles((d, name) -> name.toLowerCase().endsWith(".json"));
        if (files == null) {
            return out;
        }
        for (File f : files) {
            try {
                String text = new String(Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8);
                out.addAll(parse(text));
            } catch (Exception ignored) {
                // 手工改坏的 json 跳过就算了，不能让插件加载失败
            }
        }
        return out;
    }

    /** 解析一份 v3-lite 模板（来源列记「历史文件」，用于老数据迁移）。 */
    public static List<Endpoint> parse(String text) {
        return parse(text, "历史文件");
    }

    /**
     * 读一批文件（界面「从文件导入」支持多选）。读不动或格式不对的文件直接跳过，
     * 不让一个坏文件毁掉整次导入。
     */
    public static List<Endpoint> loadFiles(List<File> files, String tool) {
        List<Endpoint> out = new ArrayList<>();
        if (files == null) {
            return out;
        }
        for (File f : files) {
            try {
                out.addAll(parse(new String(Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8), tool));
            } catch (Exception ignored) {
                // 坏文件跳过
            }
        }
        return out;
    }

    /**
     * 解析一份 v3-lite 模板。
     *
     * @param tool 这些样本在「来源」列显示成什么（迁移用「历史文件」、界面导入用「导入」）
     */
    public static List<Endpoint> parse(String text, String tool) {
        List<Endpoint> out = new ArrayList<>();
        Object root = MiniJson.tryParse(text);
        if (!(root instanceof Map)) {
            return out;
        }
        Map<?, ?> doc = (Map<?, ?>) root;
        Map<?, ?> base = doc.get("base") instanceof Map ? (Map<?, ?>) doc.get("base") : null;
        if (base == null) {
            return out;
        }
        String scheme = str(base.get("scheme"), "https");
        String host = str(base.get("host"), "");
        int port = num(base.get("port"), "https".equals(scheme) ? 443 : 80);
        if (host.isEmpty()) {
            return out;
        }
        Object itemsRaw = doc.get("items");
        if (!(itemsRaw instanceof List)) {
            return out;
        }

        // base.headers 是整站共用的鉴权头，注回每个样本，导出时才能再收集出来。
        // 老文件里可能混着 Cache-Control / Accept 之类，过一遍 HeaderPolicy 排掉，
        // 否则它们会跟着进参数统计，把「请求头」来源搅乱
        List<String[]> sharedHeaders = new ArrayList<>();
        if (base.get("headers") instanceof Map) {
            for (Map.Entry<?, ?> e : ((Map<?, ?>) base.get("headers")).entrySet()) {
                String name = String.valueOf(e.getKey());
                if (name.isEmpty() || !HeaderPolicy.isSharedHeader(name)) {
                    continue;
                }
                sharedHeaders.add(new String[]{name, str(e.getValue(), "")});
            }
        }

        for (Object o : (List<?>) itemsRaw) {
            if (!(o instanceof Map)) {
                continue;
            }
            Map<?, ?> item = (Map<?, ?>) o;
            String method = str(item.get("method"), "GET").toUpperCase();
            String uriRaw = str(item.get("uri"), "");
            // 本插件写出去的 uri 是纯路径，但 schema 也允许带 query，两种都得认
            String uri = Urls.path(uriRaw);
            if (uri.isEmpty()) {
                continue;
            }
            List<Map<?, ?>> params = new ArrayList<>();
            if (item.get("params") instanceof List) {
                for (Object p : (List<?>) item.get("params")) {
                    if (p instanceof Map) {
                        params.add((Map<?, ?>) p);
                    }
                }
            }

            List<String[]> query = new ArrayList<>();
            List<String[]> cookies = new ArrayList<>();
            for (Map<?, ?> p : params) {
                String in = str(p.get("in"), "");
                String name = str(p.get("name"), "");
                String value = str(p.get("value"), "");
                if ("query".equals(in) && !name.isEmpty()) {
                    query.add(new String[]{name, value});
                } else if ("cookie".equals(in) && !name.isEmpty()) {
                    cookies.add(new String[]{name, value});
                }
            }
            if (query.isEmpty()) {
                // uri 自己带的 query 也算数（有些模板是这么写的）
                query.addAll(Urls.queryPairs(Urls.query(uriRaw)));
            }

            String[] ct = new String[1];
            String body = buildBody(params, ct);
            // url 必须把 query 拼回去：模板的 uri 是纯路径，参数在 params 里，
            // 不拼的话「发送到 Repeater」会变成一条没有查询参数的请求
            String qs = Urls.joinQuery(query);
            String url = scheme + "://" + host + (isDefault(port, scheme) ? "" : ":" + port) + uri
                    + (qs.isEmpty() ? "" : "?" + qs);

            out.add(new Endpoint(method, scheme, host, port, uri, url, tool,
                    query, cookies,
                    new ArrayList<>(sharedHeaders), body.getBytes(StandardCharsets.UTF_8),
                    ct[0], body,
                    null, "",
                    0, 0,
                    new ArrayList<>()));
        }
        return out;
    }

    /**
     * 从参数行反推请求体。
     * <p>
     * 能推是因为模板的写法是确定的：json 行是扁平路径、数组整棵一行、form 是 k=v、
     * raw 一行装整个 body。multipart 只能近似（模板没存 boundary），够发出去就行。
     */
    private static String buildBody(List<Map<?, ?>> params, String[] contentTypeOut) {
        List<Map<?, ?>> json = pick(params, "json");
        if (!json.isEmpty()) {
            contentTypeOut[0] = "application/json";
            Object root = null;
            for (Map<?, ?> row : json) {
                String name = str(row.get("name"), "");
                Object value = row.get("value");
                if (name.isEmpty()) {
                    root = value; // 顶层就是数组/对象，整行给完
                } else {
                    if (!(root instanceof Map)) {
                        root = new LinkedHashMap<String, Object>();
                    }
                    setPath(root, name, value);
                }
            }
            return root == null ? "" : MiniJson.write(root);
        }

        List<Map<?, ?>> form = pick(params, "form");
        if (!form.isEmpty()) {
            contentTypeOut[0] = "application/x-www-form-urlencoded";
            StringBuilder sb = new StringBuilder();
            for (Map<?, ?> row : form) {
                if (sb.length() > 0) {
                    sb.append('&');
                }
                sb.append(Urls.formEncode(str(row.get("name"), "")))
                        .append('=')
                        .append(Urls.formEncode(str(row.get("value"), "")));
            }
            return sb.toString();
        }

        List<Map<?, ?>> multipart = pick(params, "multipart");
        if (!multipart.isEmpty()) {
            String boundary = "yuc-imported-boundary";
            contentTypeOut[0] = "multipart/form-data; boundary=" + boundary;
            StringBuilder sb = new StringBuilder();
            for (Map<?, ?> row : multipart) {
                String name = str(row.get("name"), "");
                String value = str(row.get("value"), "");
                boolean file = "file".equals(str(row.get("type"), ""));
                sb.append("--").append(boundary).append("\r\n");
                sb.append("Content-Disposition: form-data; name=\"").append(name).append('"');
                if (file) {
                    String fileName = value.startsWith("./") ? value.substring(2) : value;
                    sb.append("; filename=\"").append(fileName).append('"');
                    sb.append("\r\nContent-Type: application/octet-stream");
                    value = "";
                }
                sb.append("\r\n\r\n").append(value).append("\r\n");
            }
            sb.append("--").append(boundary).append("--\r\n");
            return sb.toString();
        }

        List<Map<?, ?>> raw = pick(params, "raw");
        if (!raw.isEmpty()) {
            Map<?, ?> row = raw.get(0);
            String media = str(row.get("mediaType"), "application/octet-stream");
            contentTypeOut[0] = media;
            return str(row.get("value"), "");
        }

        contentTypeOut[0] = null;
        return "";
    }

    private static List<Map<?, ?>> pick(List<Map<?, ?>> params, String in) {
        List<Map<?, ?>> out = new ArrayList<>();
        for (Map<?, ?> p : params) {
            if (in.equals(str(p.get("in"), ""))) {
                out.add(p);
            }
        }
        return out;
    }

    // ---------------------------------------------------------------- 路径写入

    /** {@code a.b.c} / {@code a.["x.y"]} → 段列表。 */
    static List<String> splitPath(String path) {
        List<String> out = new ArrayList<>();
        StringBuilder cur = new StringBuilder();
        int i = 0;
        while (i < path.length()) {
            char c = path.charAt(i);
            if (c == '[' && i + 1 < path.length() && path.charAt(i + 1) == '"') {
                int close = path.indexOf("\"]", i + 2);
                if (close > 0) {
                    if (cur.length() > 0) {
                        out.add(cur.toString());
                        cur.setLength(0);
                    }
                    out.add(path.substring(i + 2, close));
                    i = close + 2;
                    if (i < path.length() && path.charAt(i) == '.') {
                        i++;
                    }
                    continue;
                }
            }
            if (c == '.') {
                if (cur.length() > 0) {
                    out.add(cur.toString());
                    cur.setLength(0);
                }
                i++;
                continue;
            }
            cur.append(c);
            i++;
        }
        if (cur.length() > 0) {
            out.add(cur.toString());
        }
        return out;
    }

    @SuppressWarnings("unchecked")
    static void setPath(Object root, String path, Object value) {
        List<String> segs = splitPath(path);
        Object node = root;
        for (int i = 0; i < segs.size(); i++) {
            boolean last = i == segs.size() - 1;
            if (!(node instanceof Map)) {
                return;
            }
            Map<String, Object> map = (Map<String, Object>) node;
            if (last) {
                map.put(segs.get(i), value);
            } else {
                Object next = map.get(segs.get(i));
                if (!(next instanceof Map)) {
                    next = new LinkedHashMap<String, Object>();
                    map.put(segs.get(i), next);
                }
                node = next;
            }
        }
    }

    private static boolean isDefault(int port, String scheme) {
        return ("https".equals(scheme) && port == 443) || ("http".equals(scheme) && port == 80);
    }

    private static String str(Object v, String fallback) {
        if (v == null) {
            return fallback;
        }
        return v instanceof String ? (String) v : MiniJson.write(v);
    }

    private static int num(Object v, int fallback) {
        if (v instanceof Number) {
            return ((Number) v).intValue();
        }
        try {
            return Integer.parseInt(String.valueOf(v));
        } catch (RuntimeException e) {
            return fallback;
        }
    }
}
