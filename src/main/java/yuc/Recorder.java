package yuc;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.requests.HttpRequest;

/**
 * 实时抓包入口：只读，不拦、不改，除了「继续」之外什么都不做。
 * <p>
 * 用 HttpHandler 而不是分别挂 Proxy / Repeater 处理器，是因为它一处就能拿到
 * 所有模块的请求 + 响应配对（Proxy、Repeater、Intruder、Scanner 全覆盖），
 * 再用 toolSource 区分来源，正好满足「监听 repeater 和 proxy」。
 * <p>
 * 判定规则全部委托给 {@link Capture}，和「导入历史」共用同一份。
 */
public final class Recorder implements HttpHandler {

    private final MontoyaApi api;
    private final EndpointStore store;

    public Recorder(MontoyaApi api, EndpointStore store) {
        this.api = api;
        this.store = store;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
        return RequestToBeSentAction.continueWith(request);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
        try {
            capture(response);
        } catch (Throwable t) {
            // 抓包逻辑绝不能影响 Burp 正常收发
            api.logging().logToError("[yuc] 采集异常：" + t);
        }
        return ResponseReceivedAction.continueWith(response);
    }

    private void capture(HttpResponseReceived response) {
        if (!store.isRecording()) {
            return;
        }
        HttpRequest request = response.initiatingRequest();
        if (request == null || request.httpService() == null) {
            return;
        }
        String tool = toolName(response);
        if (!toolAllowed(tool)) {
            return;
        }

        String method = request.method() == null ? "GET" : request.method().toUpperCase();
        if (!Capture.methodOk(method)) {
            return;
        }

        String url = request.url();
        if (!Capture.urlOk(url)) {
            return; // 带 # 的直接排除（锚点不是发给后端的）
        }

        // 先看响应类型再判路径：静态资源那条规则是给 JSON 用的，
        // HTML 页面（/index.html、/login.jsp）恰恰是要收的东西，不能按「末段含点号」挡掉
        String responseType = response.headerValue("Content-Type");
        String kind = Capture.kindOf(responseType);
        if (kind == null || !store.recordTypes().contains(kind)) {
            return; // 图片 / CSS / JS，或者用户没勾这一类
        }
        if (Capture.TYPE_JSON.equals(kind) && !Urls.looksLikeApi(Urls.path(url))) {
            return; // 末段含点号 = 静态资源（只对 JSON 生效）
        }

        byte[] rawBody = response.body() == null ? new byte[0] : response.body().getBytes();
        String responseText = Capture.bodyOf(rawBody, responseType, kind);
        if (responseText == null) {
            return;
        }

        String requestType = request.headerValue("Content-Type");
        byte[] requestBytes = request.body() == null ? new byte[0] : request.body().getBytes();

        store.add(Capture.build(
                tool, method, url,
                request.httpService().secure() ? "https" : "http",
                request.httpService().host(), request.httpService().port(),
                Capture.headers(request.headers()), request.headerValue("Cookie"),
                requestBytes, requestType,
                responseType, responseText,
                response.statusCode(), rawBody.length
        ));
    }

    /** 勾选的来源里包含这个模块才记；一个都没勾 = 全部。 */
    private boolean toolAllowed(String tool) {
        java.util.Set<String> filter = store.toolFilter();
        return filter.isEmpty() || filter.contains(tool);
    }

    /**
     * 直接返回 Burp 给的可读名（{@code Proxy}、{@code Repeater}、{@code Extensions}、
     * {@code Burp AI}…），不做归并——把不认识的压成「其他」等于丢信息。
     */
    private static String toolName(HttpResponseReceived response) {
        try {
            ToolType type = response.toolSource().toolType();
            if (type == null) {
                return "Unknown";
            }
            return type.toolName();
        } catch (RuntimeException e) {
            return "Unknown";
        }
    }
}
