package yuc;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

/**
 * Yuc —— 把 Proxy / Repeater 里跑出来的 JSON 接口，自动整理成 v3-lite 模板。
 * <p>
 * 采集是纯被动的：只挂一个 HttpHandler 观察流量，不改请求、不重放、不主动发包。
 */
public class YucExtension implements BurpExtension {

    /** 扩展名 / 标签页名：Extensions 列表和顶部标签都用它，不带版本号（版本在面板标题里）。 */
    public static final String NAME = "Yuc";
    public static final String VERSION = "1.0";
    public static final String AUTHOR = "xccc819";
    public static final String GITHUB = "https://github.com/xccc819/yuc";

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName(NAME);
        banner(api);

        EndpointStore store = new EndpointStore(api);
        Recorder recorder = new Recorder(api, store);
        api.http().registerHttpHandler(recorder);

        YucPanel panel = new YucPanel(api, store);
        api.userInterface().registerSuiteTab(NAME, panel);
        api.userInterface().applyThemeToComponent(panel);

        api.extension().registerUnloadingHandler(() -> {
            store.flushAll();
            store.shutdown();
        });

        api.logging().logToOutput("[yuc] 已加载：勾选 yuc 标签页里的「开始采集」后才开始记录。"
                + " 输出目录：" + store.dir().getAbsolutePath());
    }

    /** Extensions → Output 里第一眼看到的三行。 */
    private static void banner(MontoyaApi api) {
        api.logging().logToOutput("[#] Author: " + AUTHOR);
        api.logging().logToOutput("[#] Github: " + GITHUB);
        api.logging().logToOutput("[#] Version: " + VERSION);
    }
}
