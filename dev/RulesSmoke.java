import java.io.File;
import java.nio.file.Files;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import yuc.Capture;
import yuc.Endpoint;
import yuc.EndpointStore;
import yuc.Params;
import yuc.Settings;
import yuc.SettingsDialog;

/**
 * 设置页背后的规则：黑/白名单匹配、响应字段上限、解析上限、偏好持久化。
 * <p>
 * 这里测的是"判定"，不是界面长什么样——界面在 headless 下只验证"点了不炸"。
 */
public class RulesSmoke {

    static int passed = 0;
    static int failed = 0;

    static void check(String name, boolean ok) {
        if (ok) {
            passed++;
            System.out.println("  PASS " + name);
        } else {
            failed++;
            System.out.println("  FAIL " + name);
        }
    }

    public static void main(String[] args) throws Exception {
        // 设置页是 Swing 弹框：没有这行，在有显示器的机器上会真的弹出来把自测挂住
        System.setProperty("java.awt.headless", "true");
        glob();
        defaults();
        persistent();
        limits();
        captureGate();
        dbPersist();
        System.out.println(failed == 0 ? "ALL PASS" : "FAILED: " + failed);
        if (failed > 0) {
            System.exit(1);
        }
    }

    // ---------------------------------------------------------------- 匹配

    static void glob() {
        Settings s = Settings.defaults();
        s.setRules("""
                # 注释行要被忽略

                *google.*
                *.github.com
                /api/admin*
                /private
                """, "");

        check("子域命中 *google.*", !s.allows("www.google.com", "/"));
        check("其他后缀也命中", !s.allows("google.com.hk", "/"));
        check("通配前缀命中 *.github.com", !s.allows("api.github.com", "/"));
        check("根域不命中 *.github.com（子域才中）", s.allows("github.com", "/"));
        check("路径规则命中 /api/admin/users", !s.allows("a.com", "/api/admin/users"));
        check("路径规则不误伤同域其他路径", s.allows("a.com", "/api/users"));
        check("精确路径规则命中 /private", !s.allows("a.com", "/private"));
        check("普通站点放行", s.allows("api.example.com", "/v1/users"));
        check("注释/空行被忽略", s.blacklist().size() == 4);
    }

    static void defaults() {
        Settings s = Settings.defaults();
        List<String> black = s.blacklist();
        check("默认黑名单 8 条", black.size() == 8);
        check("默认含 *google.*", black.contains("*google.*"));
        check("默认含 *gov.cn", black.contains("*gov.cn"));
        check("默认挡 google", !s.allows("www.google.com", "/"));
        check("默认挡 github", !s.allows("api.github.com", "/"));
        check("默认挡 shodan", !s.allows("www.shodan.io", "/"));
        check("默认挡 fofa", !s.allows("fofa.info", "/"));
        check("默认挡 adblockplus", !s.allows("easylist.adblockplus.org", "/"));
        check("默认挡 bing", !s.allows("cn.bing.com", "/"));
        check("默认挡 gov.cn", !s.allows("www.gov.cn", "/"));
        check("默认挡 edu.cn", !s.allows("mail.tsinghua.edu.cn", "/"));
        check("默认放行普通接口", s.allows("api.example.com", "/v1/users"));
        check("默认字段上限 500", s.maxResponseFields() == 500);
        check("默认解析上限 4MB", s.maxParseBytes() == 4L * 1024 * 1024);
        check("摘要带黑名单与上限", s.summary().contains("黑名单 8 条") && s.summary().contains("500"));

        // 白名单非空就只收命中的
        s.setRules("", "*.example.com");
        check("白名单命中才收", s.allows("api.example.com", "/x"));
        check("白名单外一律不收", !s.allows("api.other.com", "/x"));
        check("白名单为空 = 不过滤", Settings.defaults().allows("anything.io", "/"));
    }

    static void persistent() {
        Map<String, String> map = new LinkedHashMap<>();
        Settings.Prefs prefs = new Settings.Prefs() {
            @Override
            public String get(String key) {
                return map.get(key);
            }

            @Override
            public void set(String key, String value) {
                map.put(key, value);
            }
        };
        Settings a = new Settings(prefs);
        check("首次加载拿到默认黑名单", a.blacklist().size() == 8);
        a.setRules("*internal.corp\n/api/debug*", "*.corp");
        a.setMaxParseBytes(8L * 1024 * 1024);
        a.setMaxResponseFields(120);
        a.save();

        Settings b = new Settings(prefs);
        check("重启后名单还在", b.blacklist().size() == 2 && b.whitelist().size() == 1);
        check("重启后解析上限还在", b.maxParseBytes() == 8L * 1024 * 1024);
        check("重启后字段上限还在", b.maxResponseFields() == 120);
        check("规则真的生效", !b.allows("internal.corp", "/") && b.allows("api.corp", "/x"));

        // 用户把黑名单清空，不该又被默认值顶回来
        b.setRules("", "");
        b.save();
        Settings c = new Settings(prefs);
        check("清空后不会再冒出默认值", c.blacklist().isEmpty() && c.allows("www.google.com", "/"));

        check("范围钳制：负数→0", clampFields(-5) == 0);
        check("范围钳制：超大→上限", clampFields(999999) == 50000);
        check("解析上限钳制：太小→64KB", clampParse(1) == 64 * 1024L);
    }

    static int clampFields(int v) {
        Settings s = Settings.defaults();
        s.setMaxResponseFields(v);
        return s.maxResponseFields();
    }

    static long clampParse(long v) {
        Settings s = Settings.defaults();
        s.setMaxParseBytes(v);
        return s.maxParseBytes();
    }

    // ---------------------------------------------------------------- 上限

    static void limits() throws Exception {
        Endpoint ep = endpoint("/v1/many", 20);

        List<Params.ParamStat> all = Params.stats(List.of(ep), null, 0);
        long respAll = all.stream().filter(x -> "响应".equals(x.where)).count();
        // 20 个 f* + code + 容器行 data = 22；库里只存叶子（21 行），容器行是界面上现算的
        check("不限时响应字段都在（叶子 21 + 容器行 1）", respAll == 22);

        List<Params.ParamStat> cut = Params.stats(List.of(ep), null, 5);
        long respCut = cut.stream().filter(x -> "响应".equals(x.where)).count();
        check("上限 5 → 参数表只出 5 个响应字段", respCut == 5);
        check("上限不影响请求侧参数", cut.stream().anyMatch(x -> "查询".equals(x.where)));

        // 落库也按同一个上限：否则界面和库里对不上
        File dir1 = Files.createTempDirectory("yuc-limit").toFile();
        EndpointStore s1 = new EndpointStore(null, dir1);
        s1.setRecording(true);
        s1.settings().setMaxResponseFields(5);
        s1.add(endpoint("/v1/many", 20));
        s1.flushAll();
        check("库里响应字段也被截到 5", countResponseRows(dir1) == 5);
        s1.shutdown();

        File dir2 = Files.createTempDirectory("yuc-limit-all").toFile();
        EndpointStore s2 = new EndpointStore(null, dir2);
        s2.setRecording(true);
        s2.settings().setMaxResponseFields(0);
        s2.add(endpoint("/v1/many", 20));
        s2.flushAll();
        check("0 = 不限，21 个响应字段都落库", countResponseRows(dir2) == 21);
        s2.shutdown();
    }

    static void captureGate() throws Exception {
        byte[] big = new byte[200 * 1024];
        java.util.Arrays.fill(big, (byte) ' ');
        big[0] = '{';
        big[1] = '}';
        String limited = Capture.bodyOf(big, "application/json", Capture.TYPE_JSON, 64 * 1024);
        check("超过解析上限 → 只记长度（返回空串）", "".equals(limited));
        String normal = Capture.bodyOf("{\"a\":1}".getBytes(), "application/json", Capture.TYPE_JSON, 4 * 1024 * 1024);
        check("没超限时正常解析", normal != null && normal.contains("a"));

        File dir = Files.createTempDirectory("yuc-gate").toFile();
        EndpointStore store = new EndpointStore(null, dir);
        check("store 默认挡 github", !store.allows("api.github.com", "/x"));
        check("store 默认放行普通站点", store.allows("api.example.com", "/x"));
        store.settings().setRules("/api/admin*", "");
        check("改完规则立刻生效", !store.allows("api.example.com", "/api/admin/x"));
        store.settings().setRules("", "");
        check("白名单为空时放行", store.allows("api.github.com", "/x"));

        check("headless 下打开设置页不抛异常、返回 false",
                !SettingsDialog.show(null, store));
        store.shutdown();
    }

    /** 设置必须跟着库走：关掉插件再开、换台机器拷 yuc.db，名单和上限都还在。 */
    static void dbPersist() throws Exception {
        File dir = Files.createTempDirectory("yuc-settings-db").toFile();

        EndpointStore s1 = new EndpointStore(null, dir);
        s1.settings().setRules("*.example.com\n/api/admin*", "*.corp");
        s1.settings().setMaxResponseFields(77);
        s1.settings().setMaxParseBytes(8L * 1024 * 1024);
        s1.saveSettings();
        s1.shutdown();

        EndpointStore s2 = new EndpointStore(null, dir);
        check("重启后黑名单从库里读回", !s2.allows("api.example.com", "/x"));
        check("重启后路径规则也读回", !s2.allows("a.corp", "/api/admin/y"));
        check("重启后白名单从库里读回", !s2.allows("other.com", "/x"));
        check("重启后字段上限从库里读回", s2.settings().maxResponseFields() == 77);
        check("重启后解析上限从库里读回", s2.settings().maxParseBytes() == 8L * 1024 * 1024);
        s2.shutdown();

        // 设置不是接口数据：清空全部数据之后，采集策略还要留着
        EndpointStore s3 = new EndpointStore(null, dir);
        s3.clearAll();
        check("清空数据不动设置", s3.settings().maxResponseFields() == 77
                && !s3.allows("api.example.com", "/x"));
        s3.shutdown();

        check("settings 表里正好 4 条", countSettings(dir) == 4);
    }

    static int countSettings(File dir) throws Exception {
        String url = "jdbc:sqlite:" + new File(dir, EndpointStore.DB_FILE).getAbsolutePath().replace('\\', '/');
        try (Connection c = DriverManager.getConnection(url);
             java.sql.Statement st = c.createStatement();
             ResultSet rs = st.executeQuery("SELECT COUNT(*) FROM settings")) {
            return rs.next() ? rs.getInt(1) : -1;
        }
    }

    // ---------------------------------------------------------------- 工具

    static Endpoint endpoint(String path, int responseFields) {
        StringBuilder body = new StringBuilder("{\"code\":0,\"data\":{");
        for (int i = 0; i < responseFields; i++) {
            if (i > 0) {
                body.append(',');
            }
            body.append("\"f").append(i).append("\":").append(i);
        }
        body.append("}}");

        List<String[]> query = new ArrayList<>();
        query.add(new String[]{"page", "1"});
        return new Endpoint("GET", "https", "api.example.com", 443, path,
                "https://api.example.com" + path + "?page=1", "Proxy",
                query, new ArrayList<>(), "application/json", "",
                "application/json", body.toString(), 200, body.length());
    }

    static int countResponseRows(File dir) throws Exception {
        String url = "jdbc:sqlite:" + new File(dir, EndpointStore.DB_FILE).getAbsolutePath().replace('\\', '/');
        try (Connection c = DriverManager.getConnection(url);
             java.sql.Statement s = c.createStatement();
             ResultSet rs = s.executeQuery(
                     "SELECT COUNT(*) FROM endpoint_params WHERE location='响应'")) {
            return rs.next() ? rs.getInt(1) : -1;
        }
    }
}
