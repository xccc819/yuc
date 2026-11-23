package yuc;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;

import java.util.List;

/**
 * 主动补捞：把 Burp <b>Proxy history</b> 里已经跑过的流量按同一套规则再扫一遍。
 * <p>
 * 为什么是 Proxy history 而不是 Logger：Montoya 2026.7 里没有任何接口能读 Logger 面板
 * （{@code api.logger()} 只能写 output/error）。能读的只有 {@code api.proxy().history()}
 * 和 {@code api.siteMap()}，前者就是 Logger 里 tool=Proxy 的那批记录，也正是补捞需要的。
 * Repeater / Intruder 的历史读不到，但它们实时就被 {@link Recorder} 收走了。
 * <p>
 * 这里的过滤判定全部走 {@link Capture}，与实时采集完全一致；去重（长度 + 请求参数形状）
 * 和「留最长响应」仍然交给 {@link EndpointStore#add}，所以重复点这个按钮是安全的。
 */
public final class HistoryImport {

    /** 进度回调（在后台线程里调，UI 侧自己切回 EDT）。 */
    public interface Progress {
        void onProgress(int done, int total);
    }

    /** 一次导入的结果，界面上直接报这个数。 */
    public static final class Result {
        /** 历史总条数 */
        public int scanned;
        /** 通过全部过滤规则的条数 */
        public int kept;
        /** 新增的接口数 */
        public int added;
        /** 已有接口但这是新的一档（长度没见过、请求参数名也变了）的条数 */
        public int updated;
        /** 通过规则但存储里已经有这一档（同一长度，或参数名一样只是长度变了），因此没动的条数 */
        public int unchanged;
        /** 被规则挡掉的条数（含无响应） */
        public int dropped;
        /** 单条处理出错（畸形报文、解析异常）的条数 */
        public int failed;
        /** 整体失败原因（读不到 history 之类） */
        public String error;

        public String summary() {
            if (error != null) {
                return "读取 Proxy 历史失败：" + error;
            }
            return "扫描 " + scanned + " 条历史\n"
                    + "通过规则 " + kept + " 条：新增接口 " + added + " 个"
                    + (updated > 0 ? " · 新增长度档位 " + updated + " 条" : "")
                    + (unchanged > 0 ? " · 已留档 " + unchanged + " 条（长度或参数没变，跳过）" : "") + "\n"
                    + "规则过滤掉 " + dropped + " 条" + (failed > 0 ? " · 异常 " + failed + " 条" : "");
        }
    }

    /** 单条结果：被规则挡掉 / 通过规则但存储没动 / 真的写进去了。 */
    private static final int DROP = 0;
    private static final int KEPT = 1;
    private static final int STORED = 2;

    private HistoryImport() {
    }

    public static Result run(MontoyaApi api, EndpointStore store, Progress progress) {
        Result r = new Result();
        List<ProxyHttpRequestResponse> history;
        try {
            history = api.proxy().history();
        } catch (Throwable t) {
            r.error = String.valueOf(t);
            return r;
        }
        if (history == null || history.isEmpty()) {
            return r;
        }
        r.scanned = history.size();
        int before = store.endpointCount();

        int done = 0;
        int stored = 0;
        for (ProxyHttpRequestResponse item : history) {
            done++;
            try {
                switch (importOne(item, store)) {
                    case STORED:
                        stored++;
                        r.kept++;
                        break;
                    case KEPT:
                        r.unchanged++;
                        r.kept++;
                        break;
                    default:
                        r.dropped++;
                        break;
                }
            } catch (Throwable t) {
                r.failed++;
            }
            if (progress != null && (done % 100 == 0 || done == r.scanned)) {
                progress.onProgress(done, r.scanned);
            }
        }

        int after = store.endpointCount();
        r.added = Math.max(0, after - before);
        r.updated = Math.max(0, stored - r.added);
        store.flushAll(); // 补捞是一次性动作，直接落盘，不等 1.2 秒防抖
        return r;
    }

    /** @return {@link #DROP} / {@link #KEPT} / {@link #STORED} */
    private static int importOne(ProxyHttpRequestResponse item, EndpointStore store) {
        if (item == null || !item.hasResponse()) {
            return DROP;
        }
        HttpRequest request = item.request() != null ? item.request() : item.finalRequest();
        HttpResponse response = item.response();
        if (request == null || response == null) {
            return DROP;
        }

        // 先做最便宜的判断，避免为图片 / HTML 去解码 body
        String method = request.method();
        method = method == null ? "GET" : method.toUpperCase();
        if (!Capture.methodOk(method)) {
            return DROP;
        }

        String url = request.url();
        if (!Capture.urlOk(url)) {
            return DROP;
        }

        String responseType = response.headerValue("Content-Type");
        String kind = Capture.kindOf(responseType);
        if (kind == null || !store.recordTypes().contains(kind)) {
            return DROP;
        }
        // 「末段含点号 = 静态资源」只对 JSON 生效，HTML 页面就是要收的
        if (Capture.TYPE_JSON.equals(kind) && !Urls.looksLikeApi(Urls.path(url))) {
            return DROP;
        }

        byte[] rawBody = response.body() == null ? new byte[0] : response.body().getBytes();
        String responseText = Capture.bodyOf(rawBody, responseType, kind);
        if (responseText == null) {
            return DROP;
        }

        HttpService service = item.httpService() != null ? item.httpService() : request.httpService();
        if (service == null) {
            return DROP;
        }

        String requestType = request.headerValue("Content-Type");
        byte[] requestBytes = request.body() == null ? new byte[0] : request.body().getBytes();

        boolean stored = store.add(Capture.build(
                "Proxy", method, url,
                service.secure() ? "https" : "http", service.host(), service.port(),
                Capture.headers(request.headers()), request.headerValue("Cookie"),
                requestBytes, requestType,
                responseType, responseText,
                response.statusCode(), rawBody.length
        ));
        return stored ? STORED : KEPT;
    }
}
