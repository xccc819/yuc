package yuc;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * 一个接口样本（不可变）。同一个接口多次被抓到时，只保留响应最长的那一份。
 * <p>
 * 除了给界面/模板用的字段，还留了原始请求头与请求体字节——「发送到 Repeater」要靠它们
 * 把请求原样拼回去，不能只剩解码后的参数。
 */
public final class Endpoint {

    public final String method;
    public final String scheme;
    public final String host;
    public final int port;
    public final String path;
    public final String url;
    public final String tool;

    public final List<String[]> query;
    public final List<String[]> cookies;
    public final List<String[]> requestHeaders;
    public final byte[] requestBodyBytes;

    public final String requestContentType;
    public final String requestBody;
    public final String responseContentType;
    public final String responseBody;
    public final int status;
    public final long responseLength;

    public final String key;
    public final long lastSeen;

    /**
     * 从数据库恢复时带回来的字段：{location, 完整路径, 示例值}。
     * <p>
     * SQLite 里不存响应正文（太大），所以重启后 {@link #responseBody} 是空的，
     * 响应字段只能靠这份清单撑起界面上的参数表。
     */
    public final List<String[]> storedFields;

    /**
     * 同一接口的所有长度档（含自己），按响应长度升序；最后一个就是主样本（最长）。
     * <p>
     * 由 {@link EndpointStore} 在组装时统一挂上，UI 右键「按长度发送到 Repeater」靠它。
     * 只有一个档位时是长度 1 的列表。
     */
    private List<Endpoint> siblings = new ArrayList<>();

    public Endpoint(String method, String scheme, String host, int port, String path, String url, String tool,
                    List<String[]> query, List<String[]> cookies,
                    String requestContentType, String requestBody,
                    String responseContentType, String responseBody,
                    int status, long responseLength) {
        this(method, scheme, host, port, path, url, tool, query, cookies,
                new ArrayList<>(), requestBody == null ? new byte[0] : requestBody.getBytes(StandardCharsets.UTF_8),
                requestContentType, requestBody, responseContentType, responseBody, status, responseLength);
    }

    public Endpoint(String method, String scheme, String host, int port, String path, String url, String tool,
                    List<String[]> query, List<String[]> cookies,
                    List<String[]> requestHeaders, byte[] requestBodyBytes,
                    String requestContentType, String requestBody,
                    String responseContentType, String responseBody,
                    int status, long responseLength) {
        this(method, scheme, host, port, path, url, tool, query, cookies, requestHeaders, requestBodyBytes,
                requestContentType, requestBody, responseContentType, responseBody, status, responseLength,
                new ArrayList<>());
    }

    public Endpoint(String method, String scheme, String host, int port, String path, String url, String tool,
                    List<String[]> query, List<String[]> cookies,
                    List<String[]> requestHeaders, byte[] requestBodyBytes,
                    String requestContentType, String requestBody,
                    String responseContentType, String responseBody,
                    int status, long responseLength, List<String[]> storedFields) {
        this.method = method == null ? "GET" : method;
        this.scheme = scheme;
        this.host = host;
        this.port = port;
        this.path = path;
        this.url = normalizeUrl(url, query);
        this.tool = tool;
        this.query = query == null ? new ArrayList<>() : query;
        this.cookies = cookies == null ? new ArrayList<>() : cookies;
        this.requestHeaders = requestHeaders == null ? new ArrayList<>() : requestHeaders;
        this.requestBodyBytes = requestBodyBytes == null ? new byte[0] : requestBodyBytes;
        this.requestContentType = requestContentType;
        this.requestBody = requestBody;
        this.responseContentType = responseContentType;
        this.responseBody = responseBody;
        this.status = status;
        this.responseLength = responseLength;
        this.storedFields = storedFields == null ? new ArrayList<>() : storedFields;
        this.key = makeKey(method, scheme, host, port, path, query);
        this.lastSeen = System.currentTimeMillis();
    }

    /**
     * 去重键：方法 + 协议 + 域名 + 端口 + 路径 + **查询参数名字集合**。
     * <p>
     * 故意不带参数值：`/list?page=1` 和 `/list?page=2` 是同一个接口，
     * 让它们互相比较响应长度，才有「保留最长响应」这件事。
     */
    public static String makeKey(String method, String scheme, String host, int port, String path, List<String[]> query) {
        Set<String> names = new LinkedHashSet<>();
        if (query != null) {
            for (String[] q : query) {
                if (q[0] != null && !q[0].isEmpty()) {
                    names.add(q[0]);
                }
            }
        }
        List<String> sorted = new ArrayList<>(names);
        sorted.sort(String::compareTo);
        return (method == null ? "GET" : method.toUpperCase()) + " " + scheme + "://" + host + ":" + port + path
                + (sorted.isEmpty() ? "" : "?" + String.join("&", sorted));
    }

    public String domainKey() {
        return host + ":" + port;
    }

    /** 同接口的所有长度档（含自己），按长度升序。 */
    public List<Endpoint> samples() {
        return siblings;
    }

    void setSamples(List<Endpoint> list) {
        this.siblings = list;
    }

    /** 同一接口收过几种不同长度的响应。 */
    public int sampleCount() {
        return Math.max(1, siblings.size());
    }

    public String displayName() {
        return method + " " + path;
    }

    public long length() {
        return responseLength;
    }

    private volatile int paramCount = -1;

    /** 这个接口在模板里有多少行参数（首次访问时算一次，之后缓存——UI 每刷新一次都会问）。 */
    public int paramCount() {
        int n = paramCount;
        if (n < 0) {
            n = Params.templateParams(this).size();
            paramCount = n;
        }
        return n;
    }

    private volatile String requestShape;
    private volatile boolean shapeDone;

    /**
     * 请求参数的形状（只有名字、没有值），见 {@link Params#requestShape}。
     * <p>
     * 判重用：长度变了但形状没变，说明还是同一条请求在反复回包，不该占新档位。
     *
     * @return {@code null} 表示认不出参数名（原始报文体），无法比较
     */
    public String requestShape() {
        if (!shapeDone) {
            requestShape = Params.requestShape(this);
            shapeDone = true;
        }
        return requestShape;
    }

    /** Host 头里该写什么：默认端口不写。 */
    public String hostForHeader() {
        int defaultPort = "https".equals(scheme) ? 443 : 80;
        return port == defaultPort || port <= 0 ? host : host + ":" + port;
    }

    /** 请求行里的目标：path + 原始 query（用原始串，不从参数表重建，避免编码被改）。 */
    public String requestTarget() {
        String q = Urls.query(url);
        if (!q.isEmpty()) {
            return path + "?" + q; // 有原始串就用原始串：%20、+、重复键、裸参数全部原样
        }
        String rebuilt = Urls.joinQuery(query);
        return rebuilt.isEmpty() ? path : path + "?" + rebuilt;
    }

    /**
     * url 里已经带回 query 就原样保留；只有「参数表有、url 却没有」时才补上。
     * <p>
     * 这个分支是为从模板/数据库恢复的样本准备的：那些样本的 url 可能只拼了路径，
     * 查询参数单独存在参数表里，不补的话发到 Repeater 就变成一条没有 query 的请求。
     */
    private static String normalizeUrl(String url, List<String[]> query) {
        if (url == null || url.isEmpty()) {
            return url;
        }
        if (!Urls.query(url).isEmpty()) {
            return url;
        }
        String rebuilt = Urls.joinQuery(query);
        if (rebuilt.isEmpty()) {
            return url;
        }
        int mark = url.indexOf('?');
        String base = mark < 0 ? url : url.substring(0, mark);
        return base + "?" + rebuilt;
    }

    /**
     * 把请求拼回字节，喂给 HttpRequest 就能进 Repeater。
     * <p>
     * 规则：保留原始头的顺序，但 Host / Content-Length 重新算（原值可能过期），
     * 丢掉 Connection / Transfer-Encoding / Proxy-Connection / Expect（让 Burp 自己决定怎么发）。
     */
    public byte[] rawRequestBytes() {
        return rawRequestBytes(null);
    }

    /**
     * @param override 非空时**用它整组代替**样本自己抓到的头——这就是「请求头配置」生效的地方：
     *                 渗透时同一个站的 token 会变，与其每次改包，不如配一份头全局套用。
     *                 传 null 或空列表则退回样本头。
     */
    public byte[] rawRequestBytes(List<String[]> override) {
        List<String[]> source = (override != null && !override.isEmpty()) ? override : requestHeaders;

        StringBuilder head = new StringBuilder();
        head.append(method).append(' ').append(requestTarget()).append(" HTTP/1.1\r\n");
        head.append("Host: ").append(hostForHeader()).append("\r\n");

        boolean contentTypeWritten = false;
        for (String[] h : source) {
            if (h[0] == null || h[0].isEmpty()) {
                continue;
            }
            String lower = h[0].toLowerCase();
            if (lower.equals("host") || lower.equals("content-length") || lower.equals("transfer-encoding")
                    || lower.equals("connection") || lower.equals("proxy-connection") || lower.equals("expect")) {
                continue;
            }
            head.append(h[0]).append(": ").append(h[1] == null ? "" : h[1]).append("\r\n");
            if (lower.equals("content-type")) {
                contentTypeWritten = true;
            }
        }
        // 配置里没写 Content-Type 时，用样本的补上：body 怎么解全靠它，缺了会被 Burp 当残包
        if (!contentTypeWritten && requestContentType != null && !requestContentType.isEmpty()) {
            head.append("Content-Type: ").append(requestContentType).append("\r\n");
        }

        // 从数据库恢复的样本没有原始字节，用存下来的正文重编（multipart 的 boundary 也在正文里）
        byte[] body = requestBodyBytes.length > 0
                ? requestBodyBytes
                : (requestBody == null || requestBody.isEmpty()
                ? new byte[0]
                : requestBody.getBytes(Capture.charsetOf(requestContentType)));

        if (body.length > 0) {
            head.append("Content-Length: ").append(body.length).append("\r\n");
        }
        head.append("\r\n");

        byte[] headBytes = head.toString().getBytes(StandardCharsets.UTF_8);
        byte[] out = new byte[headBytes.length + body.length];
        System.arraycopy(headBytes, 0, out, 0, headBytes.length);
        System.arraycopy(body, 0, out, headBytes.length, body.length);
        return out;
    }
}
