package yuc;

import java.io.File;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * SQLite 持久化。意图只有一个：**关掉 Burp 再打开，抓过的接口还在**。
 * <p>
 * 存什么、不存什么：
 * <ul>
 *   <li>存：方法、路径、URL、状态码、响应字节数、请求/响应 Content-Type、请求体正文</li>
 *   <li>存：参数（位置 + 完整层级名 + 示例值），响应字段就在这张表里（{@code location = '响应'}）</li>
 *   <li><b>不存请求头</b>：头会过期（token、cookie 每天都变），而且还原时统一用「请求头配置」</li>
 *   <li><b>不存响应正文</b>：几 MB 的 JSON 塞进库会让文件迅速膨胀；字段已经从正文里抽出来了</li>
 * </ul>
 * 代价要说清楚：从库里恢复的样本发到 Repeater 时，body 能还原（存了正文），头靠配置，
 * 响应正文看不到（详情窗口里会显示为空）。
 */
public final class Db implements AutoCloseable {

    private final Connection conn;
    private final Object lock = new Object();

    private Db(Connection conn) {
        this.conn = conn;
    }

    /** 打不开就抛异常，由 {@link EndpointStore} 决定降级为纯内存，绝不能让插件加载失败。 */
    public static Db open(File file) {
        try {
            Class.forName("org.sqlite.JDBC");
            File parent = file.getParentFile();
            if (parent != null && !parent.exists() && !parent.mkdirs()) {
                throw new SQLException("无法创建目录 " + parent);
            }
            // Windows 的反斜杠在 JDBC URL 里能瞎跑，统一换成斜杠
            Connection c = DriverManager.getConnection("jdbc:sqlite:" + file.getAbsolutePath().replace('\\', '/'));
            Db db = new Db(c);
            db.init();
            return db;
        } catch (Exception e) {
            throw new IllegalStateException("打开数据库失败：" + file + " —— " + e.getMessage(), e);
        }
    }

    private void init() throws SQLException {
        synchronized (lock) {
            try (Statement s = conn.createStatement()) {
                // WAL：读不挡写，界面查询和后台落盘不会互相卡住
                try {
                    s.execute("PRAGMA journal_mode=WAL");
                    s.execute("PRAGMA synchronous=NORMAL");
                } catch (SQLException ignored) {
                    // 只读介质 / 内存库上不支持，退回默认模式即可
                }
                s.execute("CREATE TABLE IF NOT EXISTS endpoints("
                        + " domain_key TEXT NOT NULL,"
                        + " dedupe_key TEXT NOT NULL,"
                        + " scheme TEXT, host TEXT, port INTEGER,"
                        + " method TEXT, path TEXT, url TEXT, tool TEXT,"
                        + " status INTEGER, response_length INTEGER,"
                        + " request_content_type TEXT, request_body TEXT, response_content_type TEXT,"
                        + " updated_at INTEGER NOT NULL,"
                        + " PRIMARY KEY(domain_key, dedupe_key))");
                // 同一个接口的多个长度档：[200,400,1200]，升序；主样本是最后一个（最长）
                try {
                    s.execute("ALTER TABLE endpoints ADD COLUMN lengths TEXT");
                } catch (SQLException ignored) {
                    // 新库建表时已经带了 / 老库加过一次 —— 都算正常
                }
                s.execute("CREATE TABLE IF NOT EXISTS endpoint_params("
                        + " domain_key TEXT NOT NULL,"
                        + " dedupe_key TEXT NOT NULL,"
                        + " seq INTEGER NOT NULL,"
                        + " location TEXT NOT NULL,"
                        + " name TEXT NOT NULL,"
                        + " value TEXT)");
                // 副档样本：主样本留在 endpoints 里，其余长度放这儿，避免同一份 body 存两遍
                s.execute("CREATE TABLE IF NOT EXISTS endpoint_samples("
                        + " domain_key TEXT NOT NULL,"
                        + " dedupe_key TEXT NOT NULL,"
                        + " response_length INTEGER NOT NULL,"
                        + " status INTEGER, tool TEXT, url TEXT,"
                        + " request_content_type TEXT, request_body TEXT, response_content_type TEXT,"
                        + " updated_at INTEGER NOT NULL,"
                        + " PRIMARY KEY(domain_key, dedupe_key, response_length))");
                s.execute("CREATE TABLE IF NOT EXISTS endpoint_sample_params("
                        + " domain_key TEXT NOT NULL,"
                        + " dedupe_key TEXT NOT NULL,"
                        + " response_length INTEGER NOT NULL,"
                        + " seq INTEGER NOT NULL,"
                        + " location TEXT NOT NULL,"
                        + " name TEXT NOT NULL,"
                        + " value TEXT)");
                // 域名级共用头（Cookie / Authorization …）：整站一份，不跟着每个接口重复存
                s.execute("CREATE TABLE IF NOT EXISTS domain_headers("
                        + " domain_key TEXT NOT NULL,"
                        + " name TEXT NOT NULL,"
                        + " value TEXT,"
                        + " PRIMARY KEY(domain_key, name))");
                // 行颜色标记：**故意不跟 endpoints 一起整域名重写**，见 Marks 的注释
                s.execute("CREATE TABLE IF NOT EXISTS marks("
                        + " kind TEXT NOT NULL,"
                        + " scope TEXT NOT NULL,"
                        + " target TEXT NOT NULL,"
                        + " color INTEGER NOT NULL,"
                        + " PRIMARY KEY(kind, scope, target))");
                // 设置（黑白名单 / 上限）跟库走：换机器只拷 yuc.db 也能带走采集策略
                s.execute("CREATE TABLE IF NOT EXISTS settings("
                        + " key TEXT PRIMARY KEY,"
                        + " value TEXT)");
                s.execute("CREATE INDEX IF NOT EXISTS idx_params_name ON endpoint_params(name)");
                s.execute("CREATE INDEX IF NOT EXISTS idx_params_ep ON endpoint_params(domain_key, dedupe_key)");
                s.execute("CREATE INDEX IF NOT EXISTS idx_endpoints_path ON endpoints(path)");
                s.execute("CREATE INDEX IF NOT EXISTS idx_samples_ep"
                        + " ON endpoint_samples(domain_key, dedupe_key)");
            }
        }
    }

    // ------------------------------------------------------------ 写

    /**
     * 整域名重写：先删这个域名的全部行，再把内存里的快照插进去。
     * <p>
     * 和 JSON 落盘一样的语义（整文件覆盖），好处是不用跟踪「哪条被删了」，
     * 也不会因为中途失败留下半新半旧的数据。
     * <p>
     * 主样本（最长那档）写进 {@code endpoints}，其余长度档写进 {@code endpoint_samples}——
     * 同一份请求体只存一遍，不做冗余。
     */
    public void saveDomain(String domainKey, List<EndpointStore.Group> groups) {
        saveDomain(domainKey, groups, 0);
    }

    /**
     * @param maxResponseFields 每个接口最多写多少个响应字段，0 = 不限。
     *                          响应字段是这类库里行数的大头（一个 RPC 接口能有一千多个），
     *                          卡住它最直接地控制库和内存。
     */
    public void saveDomain(String domainKey, List<EndpointStore.Group> groups, int maxResponseFields) {
        synchronized (lock) {
            try {
                conn.setAutoCommit(false);
                try (PreparedStatement a = conn.prepareStatement("DELETE FROM endpoints WHERE domain_key=?");
                     PreparedStatement b = conn.prepareStatement("DELETE FROM endpoint_params WHERE domain_key=?");
                     PreparedStatement c = conn.prepareStatement("DELETE FROM endpoint_samples WHERE domain_key=?");
                     PreparedStatement d = conn.prepareStatement("DELETE FROM endpoint_sample_params WHERE domain_key=?");
                     PreparedStatement e = conn.prepareStatement("DELETE FROM domain_headers WHERE domain_key=?")) {
                    for (PreparedStatement p : List.of(a, b, c, d, e)) {
                        p.setString(1, domainKey);
                        p.executeUpdate();
                    }
                }

                List<Endpoint> primaries = new ArrayList<>();
                for (EndpointStore.Group g : groups) {
                    if (g.primary() != null) {
                        primaries.add(g.primary());
                    }
                }
                try (PreparedStatement hd = conn.prepareStatement(
                        "INSERT INTO domain_headers(domain_key,name,value) VALUES(?,?,?)")) {
                    for (Map.Entry<String, String> h : HeaderPolicy.collect(primaries).entrySet()) {
                        hd.setString(1, domainKey);
                        hd.setString(2, h.getKey());
                        hd.setString(3, h.getValue());
                        hd.addBatch();
                    }
                    hd.executeBatch();
                }

                try (PreparedStatement ep = conn.prepareStatement(
                        "INSERT INTO endpoints(domain_key,dedupe_key,scheme,host,port,method,path,url,tool,"
                                + "status,response_length,request_content_type,request_body,response_content_type,"
                                + "updated_at,lengths) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)");
                     PreparedStatement pa = conn.prepareStatement(
                             "INSERT INTO endpoint_params(domain_key,dedupe_key,seq,location,name,value)"
                                     + " VALUES(?,?,?,?,?,?)");
                     PreparedStatement sp = conn.prepareStatement(
                             "INSERT INTO endpoint_samples(domain_key,dedupe_key,response_length,status,tool,url,"
                                     + "request_content_type,request_body,response_content_type,updated_at)"
                                     + " VALUES(?,?,?,?,?,?,?,?,?,?)");
                     PreparedStatement spa = conn.prepareStatement(
                             "INSERT INTO endpoint_sample_params(domain_key,dedupe_key,response_length,"
                                     + "seq,location,name,value) VALUES(?,?,?,?,?,?,?)")) {
                    long now = System.currentTimeMillis();
                    for (EndpointStore.Group g : groups) {
                        Endpoint primary = g.primary();
                        if (primary == null) {
                            continue;
                        }
                        List<Endpoint> all = g.all();
                        List<Object> lengths = new ArrayList<>();
                        for (Endpoint e : all) {
                            lengths.add(e.responseLength);
                        }

                        ep.setString(1, domainKey);
                        ep.setString(2, primary.key);
                        ep.setString(3, primary.scheme);
                        ep.setString(4, primary.host);
                        ep.setInt(5, primary.port);
                        ep.setString(6, primary.method);
                        ep.setString(7, primary.path);
                        ep.setString(8, primary.url);
                        ep.setString(9, primary.tool);
                        ep.setInt(10, primary.status);
                        ep.setLong(11, primary.responseLength);
                        ep.setString(12, primary.requestContentType);
                        ep.setString(13, primary.requestBody);
                        ep.setString(14, primary.responseContentType);
                        ep.setLong(15, now);
                        ep.setString(16, MiniJson.write(lengths));
                        ep.addBatch();
                        addParams(pa, domainKey, primary.key, null, primary, maxResponseFields);

                        for (Endpoint e : all) {
                            if (e.responseLength == primary.responseLength) {
                                continue;
                            }
                            sp.setString(1, domainKey);
                            sp.setString(2, e.key);
                            sp.setLong(3, e.responseLength);
                            sp.setInt(4, e.status);
                            sp.setString(5, e.tool);
                            sp.setString(6, e.url);
                            sp.setString(7, e.requestContentType);
                            sp.setString(8, e.requestBody);
                            sp.setString(9, e.responseContentType);
                            sp.setLong(10, now);
                            sp.addBatch();
                            addParams(spa, domainKey, e.key, e.responseLength, e, maxResponseFields);
                        }
                    }
                    ep.executeBatch();
                    pa.executeBatch();
                    sp.executeBatch();
                    spa.executeBatch();
                }
                conn.commit();
            } catch (SQLException ex) {
                try {
                    conn.rollback();
                } catch (SQLException ignored) {
                    // 已经断了就没得救
                }
                throw new IllegalStateException("写入数据库失败：" + domainKey + " —— " + ex.getMessage(), ex);
            } finally {
                try {
                    conn.setAutoCommit(true);
                } catch (SQLException ignored) {
                    // ignore
                }
            }
        }
    }

    /** 把一个样本的参数行批量塞进预编译语句；{@code length} 为 null 表示主样本那两张表。 */
    private static void addParams(PreparedStatement ps, String domainKey, String key, Long length,
                                  Endpoint ep, int maxResponseFields) throws SQLException {
        int seq = 0;
        for (String[] row : paramRows(ep, maxResponseFields)) {
            ps.setString(1, domainKey);
            ps.setString(2, key);
            int i = 3;
            if (length != null) {
                ps.setLong(3, length);
                i = 4;
            }
            ps.setInt(i, seq++);
            ps.setString(i + 1, row[0]);
            ps.setString(i + 2, row[1]);
            ps.setString(i + 3, row[2]);
            ps.addBatch();
        }
    }

    /** 一个样本要入库的参数行：{location, name, value}。请求侧来自模板参数，响应侧来自字段清单。 */
    private static List<String[]> paramRows(Endpoint ep, int maxResponseFields) {
        List<String[]> out = new ArrayList<>();
        for (Map<String, Object> row : Params.templateParams(ep)) {
            String in = text(row.get("in"));
            String name = text(row.get("name"));
            if (in == null || in.isEmpty()) {
                continue;
            }
            out.add(new String[]{in, name == null ? "" : name, text(row.get("value"))});
        }
        if (ep.responseBody != null && !ep.responseBody.isEmpty()) {
            final List<String[]> sink = out;
            final int limit = maxResponseFields <= 0 ? Integer.MAX_VALUE : maxResponseFields;
            final int[] count = {0};
            Params.walkKeys(MiniJson.tryParse(ep.responseBody), "", (name, value) -> {
                if (count[0] >= limit) {
                    return;
                }
                sink.add(new String[]{"响应", name,
                        value instanceof String ? (String) value : MiniJson.write(value)});
                count[0]++;
            });
        } else {
            for (String[] f : ep.storedFields) {
                out.add(new String[]{"响应", f[1], f[2]});
            }
        }
        return out;
    }

    private static String text(Object v) {
        if (v == null) {
            return null;
        }
        return v instanceof String ? (String) v : MiniJson.write(v);
    }

    // ------------------------------------------------------------ 设置（跟库走）

    public String getSetting(String key) {
        synchronized (lock) {
            try (PreparedStatement ps = conn.prepareStatement("SELECT value FROM settings WHERE key=?")) {
                ps.setString(1, key);
                try (ResultSet rs = ps.executeQuery()) {
                    return rs.next() ? rs.getString(1) : null;
                }
            } catch (SQLException e) {
                return null;
            }
        }
    }

    public void setSetting(String key, String value) {
        synchronized (lock) {
            try (PreparedStatement ps = conn.prepareStatement(
                    "INSERT INTO settings(key,value) VALUES(?,?)"
                            + " ON CONFLICT(key) DO UPDATE SET value=excluded.value")) {
                ps.setString(1, key);
                ps.setString(2, value);
                ps.executeUpdate();
            } catch (SQLException ignored) {
                // 只读介质上存不了，本次会话内仍然生效
            }
        }
    }

    /** {接口数, 参数行数}：设置页展示用。 */
    public long[] counts() {
        synchronized (lock) {
            try (Statement s = conn.createStatement();
                 ResultSet a = s.executeQuery("SELECT COUNT(*) FROM endpoints");
                 ResultSet b = s.executeQuery("SELECT COUNT(*) FROM endpoint_params")) {
                long eps = a.next() ? a.getLong(1) : 0;
                long params = b.next() ? b.getLong(1) : 0;
                return new long[]{eps, params};
            } catch (SQLException e) {
                return new long[]{0, 0};
            }
        }
    }

    public void deleteDomain(String domainKey) {
        synchronized (lock) {
            try (PreparedStatement a = conn.prepareStatement("DELETE FROM endpoints WHERE domain_key=?");
                 PreparedStatement b = conn.prepareStatement("DELETE FROM endpoint_params WHERE domain_key=?");
                 PreparedStatement c = conn.prepareStatement("DELETE FROM endpoint_samples WHERE domain_key=?");
                 PreparedStatement d = conn.prepareStatement("DELETE FROM endpoint_sample_params WHERE domain_key=?");
                 PreparedStatement e = conn.prepareStatement("DELETE FROM domain_headers WHERE domain_key=?");
                 PreparedStatement f = conn.prepareStatement("DELETE FROM marks WHERE scope=?")) {
                for (PreparedStatement p : List.of(a, b, c, d, e)) {
                    p.setString(1, domainKey);
                    p.executeUpdate();
                }
                // 只收这个域名自己的标记；跨域名的参数标记 scope 是空串，不会被误删
                f.setString(1, domainKey);
                f.executeUpdate();
            } catch (SQLException e) {
                throw new IllegalStateException("删除数据库记录失败：" + e.getMessage(), e);
            }
        }
    }

    public void deleteAll() {
        synchronized (lock) {
            try (Statement s = conn.createStatement()) {
                s.executeUpdate("DELETE FROM endpoints");
                s.executeUpdate("DELETE FROM endpoint_params");
                s.executeUpdate("DELETE FROM endpoint_samples");
                s.executeUpdate("DELETE FROM endpoint_sample_params");
                s.executeUpdate("DELETE FROM domain_headers");
                s.executeUpdate("DELETE FROM marks");
            } catch (SQLException e) {
                throw new IllegalStateException("清空数据库失败：" + e.getMessage(), e);
            }
        }
    }

    // ------------------------------------------------------------ 颜色标记

    /** 全部标记，每行 {kind, scope, target, color}。 */
    public List<String[]> loadMarks() {
        synchronized (lock) {
            List<String[]> out = new ArrayList<>();
            try (Statement s = conn.createStatement();
                 ResultSet rs = s.executeQuery("SELECT kind,scope,target,color FROM marks")) {
                while (rs.next()) {
                    out.add(new String[]{rs.getString(1), rs.getString(2), rs.getString(3),
                            String.valueOf(rs.getInt(4))});
                }
            } catch (SQLException e) {
                throw new IllegalStateException("读取颜色标记失败：" + e.getMessage(), e);
            }
            return out;
        }
    }

    public void saveMark(String kind, String scope, String target, int color) {
        synchronized (lock) {
            try (PreparedStatement ps = conn.prepareStatement(
                    "INSERT INTO marks(kind,scope,target,color) VALUES(?,?,?,?)"
                            + " ON CONFLICT(kind,scope,target) DO UPDATE SET color=excluded.color")) {
                ps.setString(1, kind);
                ps.setString(2, scope == null ? "" : scope);
                ps.setString(3, target);
                ps.setInt(4, color);
                ps.executeUpdate();
            } catch (SQLException e) {
                throw new IllegalStateException("写入颜色标记失败：" + e.getMessage(), e);
            }
        }
    }

    public void deleteMark(String kind, String scope, String target) {
        synchronized (lock) {
            try (PreparedStatement ps = conn.prepareStatement(
                    "DELETE FROM marks WHERE kind=? AND scope=? AND target=?")) {
                ps.setString(1, kind);
                ps.setString(2, scope == null ? "" : scope);
                ps.setString(3, target);
                ps.executeUpdate();
            } catch (SQLException e) {
                throw new IllegalStateException("删除颜色标记失败：" + e.getMessage(), e);
            }
        }
    }

    /** 按 种类 + 作用域 批量删（删域名时用；scope 传域名端口）。 */
    public void deleteMarks(String kind, String scope) {
        synchronized (lock) {
            try (PreparedStatement ps = conn.prepareStatement("DELETE FROM marks WHERE kind=? AND scope=?")) {
                ps.setString(1, kind);
                ps.setString(2, scope == null ? "" : scope);
                ps.executeUpdate();
            } catch (SQLException e) {
                throw new IllegalStateException("删除颜色标记失败：" + e.getMessage(), e);
            }
        }
    }

    public void deleteAllMarks() {
        synchronized (lock) {
            try (Statement s = conn.createStatement()) {
                s.executeUpdate("DELETE FROM marks");
            } catch (SQLException e) {
                throw new IllegalStateException("清空颜色标记失败：" + e.getMessage(), e);
            }
        }
    }

    // ------------------------------------------------------------ 读

    /**
     * 启动时把库里的样本全捞回内存。
     * <p>
     * 一个接口可能有多条：主样本在 {@code endpoints}，其余长度档在 {@code endpoint_samples}，
     * 两边都读出来交给 {@link EndpointStore} 按 {@code dedupe_key} 重新分组。
     * 响应正文不存，所以恢复出来的样本 {@code responseBody} 为空。
     */
    public List<Endpoint> loadAll() {
        synchronized (lock) {
            Map<String, List<String[]>> params = new LinkedHashMap<>();
            try (Statement s = conn.createStatement();
                 ResultSet rs = s.executeQuery(
                         "SELECT domain_key,dedupe_key,location,name,value FROM endpoint_params ORDER BY rowid")) {
                while (rs.next()) {
                    String k = rs.getString(1) + '\u0000' + rs.getString(2);
                    params.computeIfAbsent(k, x -> new ArrayList<>())
                            .add(new String[]{rs.getString(3), rs.getString(4), rs.getString(5)});
                }
            } catch (SQLException e) {
                throw new IllegalStateException("读取参数失败：" + e.getMessage(), e);
            }

            // 副档参数：键里多一个长度，才能分清是哪一档的参数
            Map<String, List<String[]>> sampleParams = new LinkedHashMap<>();
            try (Statement s = conn.createStatement();
                 ResultSet rs = s.executeQuery("SELECT domain_key,dedupe_key,response_length,location,name,value"
                         + " FROM endpoint_sample_params ORDER BY rowid")) {
                while (rs.next()) {
                    String k = rs.getString(1) + '\u0000' + rs.getString(2) + '\u0000' + rs.getLong(3);
                    sampleParams.computeIfAbsent(k, x -> new ArrayList<>())
                            .add(new String[]{rs.getString(4), rs.getString(5), rs.getString(6)});
                }
            } catch (SQLException e) {
                throw new IllegalStateException("读取副档参数失败：" + e.getMessage(), e);
            }

            // 域名级共用头：注回每个样本，这样导出和还原都还带着它们
            Map<String, List<String[]>> headers = new LinkedHashMap<>();
            try (Statement s = conn.createStatement();
                 ResultSet rs = s.executeQuery("SELECT domain_key,name,value FROM domain_headers")) {
                while (rs.next()) {
                    headers.computeIfAbsent(rs.getString(1), x -> new ArrayList<>())
                            .add(new String[]{rs.getString(2), rs.getString(3)});
                }
            } catch (SQLException e) {
                throw new IllegalStateException("读取共用头失败：" + e.getMessage(), e);
            }

            List<Endpoint> out = new ArrayList<>();
            Map<String, Endpoint> primaryByKey = new LinkedHashMap<>();
            try (Statement s = conn.createStatement();
                 ResultSet rs = s.executeQuery(
                         "SELECT domain_key,dedupe_key,scheme,host,port,method,path,url,tool,status,"
                                 + "response_length,request_content_type,request_body,response_content_type"
                                 + " FROM endpoints ORDER BY updated_at")) {
                while (rs.next()) {
                    String dk = rs.getString(1);
                    String key = rs.getString(2);
                    List<String[]> rows = params.getOrDefault(dk + '\u0000' + key, new ArrayList<>());

                    List<String[]> query = new ArrayList<>();
                    List<String[]> cookies = new ArrayList<>();
                    List<String[]> stored = new ArrayList<>();
                    split(rows, query, cookies, stored);

                    Endpoint ep = new Endpoint(
                            rs.getString(6), rs.getString(3), rs.getString(4), rs.getInt(5),
                            rs.getString(7), rs.getString(8), rs.getString(9),
                            query, cookies,
                            headers.getOrDefault(dk, new ArrayList<>()), new byte[0],
                            rs.getString(12), rs.getString(13),
                            rs.getString(14), "",
                            rs.getInt(10), rs.getLong(11),
                            stored);
                    out.add(ep);
                    primaryByKey.put(dk + '\u0000' + key, ep);
                }
            } catch (SQLException e) {
                throw new IllegalStateException("读取接口失败：" + e.getMessage(), e);
            }

            // 副档：scheme/host/port/method/path 跟主样本一样，长度、状态、body 各不相同
            try (Statement s = conn.createStatement();
                 ResultSet rs = s.executeQuery(
                         "SELECT domain_key,dedupe_key,response_length,status,tool,url,"
                                 + "request_content_type,request_body,response_content_type"
                                 + " FROM endpoint_samples ORDER BY domain_key,dedupe_key,response_length")) {
                while (rs.next()) {
                    String dk = rs.getString(1);
                    String key = rs.getString(2);
                    long len = rs.getLong(3);
                    Endpoint p = primaryByKey.get(dk + '\u0000' + key);
                    if (p == null) {
                        continue; // 主样本没了（理论上不会），孤儿档位直接跳过
                    }
                    List<String[]> rows = sampleParams.getOrDefault(
                            dk + '\u0000' + key + '\u0000' + len, new ArrayList<>());
                    List<String[]> query = new ArrayList<>();
                    List<String[]> cookies = new ArrayList<>();
                    List<String[]> stored = new ArrayList<>();
                    split(rows, query, cookies, stored);

                    out.add(new Endpoint(
                            p.method, p.scheme, p.host, p.port, p.path, rs.getString(6), rs.getString(5),
                            query, cookies,
                            headers.getOrDefault(dk, new ArrayList<>()), new byte[0],
                            rs.getString(7), rs.getString(8),
                            rs.getString(9), "",
                            rs.getInt(4), len,
                            stored));
                }
            } catch (SQLException e) {
                throw new IllegalStateException("读取副档样本失败：" + e.getMessage(), e);
            }
            return out;
        }
    }

    private static void split(List<String[]> rows, List<String[]> query,
                              List<String[]> cookies, List<String[]> stored) {
        for (String[] r : rows) {
            if ("query".equals(r[0])) {
                query.add(new String[]{r[1], r[2]});
            } else if ("cookie".equals(r[0])) {
                cookies.add(new String[]{r[1], r[2]});
            } else if ("响应".equals(r[0])) {
                stored.add(new String[]{r[0], r[1], r[2]});
            }
        }
    }

    /** 库里有几个接口（自测与界面统计用）。 */
    public int endpointCount() {
        synchronized (lock) {
            try (Statement s = conn.createStatement();
                 ResultSet rs = s.executeQuery("SELECT COUNT(*) FROM endpoints")) {
                return rs.next() ? rs.getInt(1) : 0;
            } catch (SQLException e) {
                return 0;
            }
        }
    }

    /** 库里一共有几条样本（主样本 + 各长度副档）。 */
    public int sampleCount() {
        synchronized (lock) {
            try (Statement s = conn.createStatement();
                 ResultSet rs = s.executeQuery(
                         "SELECT (SELECT COUNT(*) FROM endpoints) + (SELECT COUNT(*) FROM endpoint_samples)")) {
                return rs.next() ? rs.getInt(1) : 0;
            } catch (SQLException e) {
                return 0;
            }
        }
    }

    @Override
    public void close() {
        synchronized (lock) {
            try {
                conn.close();
            } catch (SQLException ignored) {
                // 关不掉也只能算了
            }
        }
    }
}
