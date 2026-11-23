package yuc;

import burp.api.montoya.http.message.HttpHeader;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

/**
 * 采集规则与样本组装的唯一出口。
 * <p>
 * 两条数据来源都走这里：实时抓包（{@link Recorder}，HttpHandler）和历史补捞
 * （{@link HistoryImport}，读 Proxy history）。共用一份判定，才不会出现
 * 「实时收了、历史却漏了」这种自相矛盾的情况。
 */
public final class Capture {

    /** v3-lite 的 method 只有这 7 个，其余方法（PROPFIND 等）无法写进模板。 */
    public static final Set<String> METHODS = Set.of("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS");

    /** 响应体超过这个长度就不再解析字段（长度照样参与「谁最长」的比较）。 */
    public static final int MAX_PARSE = 4 * 1024 * 1024;

    /**
     * 可选的记录类型。
     * <p>
     * 只有两档，而且默认只记 JSON：一个站的 HTML 页面动辄几百个，全收进来会把接口表淹掉，
     * 所以 HTML 必须手动打开（见 {@link EndpointStore#recordTypes}）。
     */
    public static final String[] TYPE_NAMES = {"JSON", "HTML"};
    public static final String TYPE_JSON = "JSON";
    public static final String TYPE_HTML = "HTML";

    private Capture() {
    }

    // ---------------------------------------------------------------- 判定

    public static boolean methodOk(String method) {
        return method != null && METHODS.contains(method);
    }

    /** 带 # 的直接排除（锚点不是发给后端的）；url 为空也丢掉。 */
    public static boolean urlOk(String url) {
        return url != null && !url.isEmpty() && url.indexOf('#') < 0;
    }

    /**
     * 响应 Content-Type → 记录类型（{@link #TYPE_JSON} / {@link #TYPE_HTML}）。
     * <p>
     * 看的是**响应**头的类型，不是路径后缀：`/api/getData` 这种没有后缀的也能认出来。
     *
     * @return 两种都不是返回 {@code null}（图片、CSS、JS、字体全在这儿被挡掉）
     */
    public static String kindOf(String contentType) {
        if (contentType == null) {
            return null;
        }
        String ct = contentType.toLowerCase();
        if (ct.contains("json")) {
            return TYPE_JSON;
        }
        if (ct.contains("html")) {
            return TYPE_HTML; // text/html、application/xhtml+xml
        }
        return null;
    }

    /**
     * 这条响应该不该收，收的话正文是什么。
     *
     * @param kind 上游 {@link #kindOf} 的结果（已确认在允许的类型里）
     * @return {@code null} = 丢弃；{@code ""} = 太大只记长度；否则是解码后的正文
     */
    public static String bodyOf(byte[] rawBody, String contentType, String kind) {
        if (rawBody == null || rawBody.length == 0) {
            return null; // 空响应没有字段可学
        }
        if (rawBody.length > MAX_PARSE) {
            return ""; // 只记长度
        }
        String text = new String(rawBody, charsetOf(contentType));
        // 头写 json 实际吐 HTML 的挡掉；HTML 反过来不校验形状——模板页、错误页、跳转页都是合法 HTML
        if (TYPE_JSON.equals(kind) && !Params.looksJson(text)) {
            return null;
        }
        return text;
    }

    // ---------------------------------------------------------------- 组装

    public static Charset charsetOf(String contentType) {
        if (contentType != null) {
            int i = contentType.toLowerCase().indexOf("charset=");
            if (i >= 0) {
                String name = contentType.substring(i + 8).split(";")[0].trim().replace("\"", "");
                try {
                    return Charset.forName(name);
                } catch (RuntimeException ignored) {
                    // 落到 UTF-8
                }
            }
        }
        return StandardCharsets.UTF_8;
    }

    /** 请求头原样留下（保序），「发送到 Repeater」才能把报文拼回去。 */
    public static List<String[]> headers(List<HttpHeader> raw) {
        List<String[]> out = new ArrayList<>();
        if (raw == null) {
            return out;
        }
        for (HttpHeader h : raw) {
            out.add(new String[]{h.name(), h.value()});
        }
        return out;
    }

    /** 请求体只留前 {@link Params#MAX_REQUEST_BODY} 字节，避免把上传体整个吞进内存。 */
    public static byte[] clip(byte[] raw) {
        if (raw == null || raw.length == 0) {
            return new byte[0];
        }
        return Arrays.copyOf(raw, Math.min(raw.length, Params.MAX_REQUEST_BODY));
    }

    /**
     * 把「已经在手的原始材料」拼成一个样本。过滤已经在上游做完，这里只负责组装。
     *
     * @param responseText 已经过 {@link #bodyOf} 处理：超限为 ""，正常为正文
     */
    public static Endpoint build(String tool, String method, String url,
                                 String scheme, String host, int port,
                                 List<String[]> headers, String cookieHeader,
                                 byte[] rawRequestBody, String requestType,
                                 String responseType, String responseText,
                                 int status, int responseLength) {
        byte[] requestBytes = clip(rawRequestBody);
        String requestBody = requestBytes.length == 0 ? "" : new String(requestBytes, charsetOf(requestType));
        return new Endpoint(
                method,
                scheme,
                host,
                port,
                Urls.path(url),
                url,
                tool,
                Urls.queryPairs(Urls.query(url)),
                Urls.cookiePairs(cookieHeader),
                headers,
                requestBytes,
                requestType,
                requestBody,
                responseType,
                responseText == null ? "" : responseText,
                status,
                responseLength
        );
    }
}
