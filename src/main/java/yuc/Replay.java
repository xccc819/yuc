package yuc;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;

/** 把抓到的样本还原成一条真正的请求，丢给 Repeater。 */
public final class Replay {

    private Replay() {
    }

    public static HttpRequest toRepeaterRequest(Endpoint ep) {
        return toRepeaterRequest(ep, null);
    }

    /**
     * @param overrideHeaders 全局请求头配置；非空时整组代替样本头（缺 Content-Type 会从样本补）
     */
    public static HttpRequest toRepeaterRequest(Endpoint ep, java.util.List<String[]> overrideHeaders) {
        HttpService service = HttpService.httpService(ep.host, ep.port, "https".equalsIgnoreCase(ep.scheme));
        return HttpRequest.httpRequest(service, ByteArray.byteArray(ep.rawRequestBytes(overrideHeaders)));
    }

    /** Repeater 标签名：`yuc POST /api/save`，太长就截断。 */
    public static String tabName(Endpoint ep) {
        String name = "yuc " + ep.method + " " + ep.path;
        return name.length() > 60 ? name.substring(0, 60) : name;
    }
}
