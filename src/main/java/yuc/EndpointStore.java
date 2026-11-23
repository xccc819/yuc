package yuc;

import burp.api.montoya.MontoyaApi;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;

/**
 * 抓到的接口都在这儿：按「域名:端口」分组；同一个接口按**响应长度**留最多
 * {@link #MAX_SAMPLES} 档，主样本是最长那档。
 * <p>
 * 三处落地：<b>内存</b>（唯一活数据）、<b>SQLite</b>（重启后还在）、<b>JSON</b>（交付物，v3-lite 模板）。
 * 前两个是同一个防抖周期里写的，1.2 秒内的连续抓包只会触发一次写盘。
 */
public final class EndpointStore {

    /** 数据变了通知 UI（可能在 Burp 的线程里回调，UI 侧要自己切回 EDT）。 */
    public interface Listener {
        void onChanged(String domainKey);
    }

    private static final long DEBOUNCE_MS = 1200;
    /** 数据库文件名，跟着「存储目录」走。 */
    public static final String DB_FILE = "yuc.db";

    /**
     * 一个接口最多留几种长度的样本。
     * <p>
     * 不设上限会出事：有些接口传错参数会返回**长度各不相同的报错页**（里面带时间戳、traceId），
     * 每来一条都算"新长度"，库就无限长。8 档足够覆盖"正常 / 少参数全量 / 参数错 / 未登录"这几种形态。
     */
    public static final int MAX_SAMPLES = 8;

    /**
     * 采集来源清单 = Burp 的全部 {@code ToolType}，名字用官方的可读名，一个都不省。
     * <p>
     * 不缩成「Proxy / Repeater / 其他」那套：那样会把 Extensions、Burp AI 这些真来源
     * 压成一个笼统的「其他」，用户既看不出流量从哪来，勾选也勾不准。
     * 顺序与 {@code ToolType.values()} 一致。
     */
    public static final String[] SOURCE_NAMES = {
            "Suite", "Target", "Proxy", "Scanner", "Intruder", "Repeater", "Logger",
            "Sequencer", "Decoder", "Comparer", "Extensions",
            "Recorded login replayer", "Organizer", "Burp AI"};

    private final MontoyaApi api;
    private final Object lock = new Object();
    private final Map<String, Domain> domains = new LinkedHashMap<>();
    private final Map<String, ScheduledFuture<?>> pending = new LinkedHashMap<>();
    private final List<Listener> listeners = new CopyOnWriteArrayList<>();
    private final ScheduledExecutorService writer;
    /** 行颜色标记（路径 / 参数）；跟样本数据分开存在 marks 表里，见 {@link Marks}。 */
    private final Marks marks = new Marks();
    /** 收录范围与响应大小（黑/白名单、解析上限、字段上限）。 */
    private final Settings settings;

    private volatile boolean recording;
    /** 空集 = 全部来源（和参数来源筛选同一套语义）。 */
    private volatile java.util.Set<String> toolFilter = java.util.Set.of();
    /**
     * 记录哪些内容类型（见 {@link Capture#TYPE_NAMES}）。
     * <p>
     * <b>默认只 JSON，HTML 默认不记</b>：一个站的 HTML 页面几百个，收进来会把接口表淹掉。
     * 注意这里和「来源」的语义不一样——**空集不是全部，而是回退成只 JSON**，
     * 否则用户把两个都取消勾选就会变成"一条都不记"，那是纯粹的坑。
     */
    private volatile java.util.Set<String> recordTypes = java.util.Set.of(Capture.TYPE_JSON);
    private volatile File dir;
    private volatile Db db;
    private long skipped;

    public EndpointStore(MontoyaApi api) {
        this(api, null);
    }

    /**
     * @param dirOverride 非空时直接用它作为存储目录，不读 preferences。
     *                    离线自测靠它把数据钉在临时目录，免得碰到真实的 ~/yuc-output。
     */
    public EndpointStore(MontoyaApi api, File dirOverride) {
        this.api = api;
        this.writer = Executors.newSingleThreadScheduledExecutor(new ThreadFactory() {
            @Override
            public Thread newThread(Runnable r) {
                Thread t = new Thread(r, "yuc-writer");
                t.setDaemon(true);
                return t;
            }
        });
        this.dir = dirOverride != null ? dirOverride
                : new File(pref("dir", System.getProperty("user.home") + File.separator + "yuc-output"));
        this.recording = "1".equals(pref("recording", "0"));
        this.toolFilter = parseToolFilter(pref("tool", ""));
        this.recordTypes = parseRecordTypes(pref("types", ""));
        // 设置存进 yuc.db（settings 表）：跟库走，不跟 Burp 工程走。
        // 构造时库还没开，先拿到默认值；openDb() 之后再 reload() 一次读到真值。
        this.settings = new Settings(new Settings.Prefs() {
            @Override
            public String get(String key) {
                Db d = db;
                return d == null ? null : d.getSetting(key);
            }

            @Override
            public void set(String key, String value) {
                Db d = db;
                if (d != null) {
                    d.setSetting(key, value);
                }
            }
        });
        openDb();
        loadFromDb();
    }

    // ------------------------------------------------------------ 数据库

    public File dbFile() {
        return new File(dir, DB_FILE);
    }

    /** 数据库是否可用（native 加载失败、目录只读时会降级为纯内存）。 */
    public boolean hasDb() {
        return db != null;
    }

    private void openDb() {
        try {
            db = Db.open(dbFile());
        } catch (RuntimeException e) {
            db = null;
            if (api != null) {
                api.logging().logToError("[yuc] SQLite 不可用，本次降级为纯内存：" + e.getMessage());
            }
        }
        // 标记跟着库走：换库 = 换一套标记，不能把上一个目录的颜色带过来
        marks.attach(db);
        // 设置也跟库走：换库 / 首次打开之后重新读一遍（没有库时退回默认值）
        settings.reload();
    }

    /** 行颜色标记的读写入口；改完自己刷新界面即可，不会触发 {@link Listener}。 */
    public Marks marks() {
        return marks;
    }

    /** 收录范围 / 响应大小设置。改完调 {@link #saveSettings()} 落偏好。 */
    public Settings settings() {
        return settings;
    }

    public void saveSettings() {
        settings.save();
    }

    /** {接口数, 参数行数}：设置页展示规模用；没有库时退回内存里的接口数。 */
    public long[] dbCounts() {
        Db d = db;
        if (d == null) {
            return new long[]{endpointCount(), 0};
        }
        try {
            return d.counts();
        } catch (RuntimeException e) {
            return new long[]{endpointCount(), 0};
        }
    }

    /** 这条请求在不在收录范围里（黑名单命中 → 否；白名单非空且没命中 → 否）。 */
    public boolean allows(String host, String path) {
        return settings.allows(host, path);
    }

    /** 启动时把库里的样本捞回内存——这就是「关掉 Burp 再打开，接口还在」的那一步。 */
    private void loadFromDb() {
        Db d = db;
        boolean loaded = false;
        if (d != null) {
            List<Endpoint> all;
            try {
                all = d.loadAll();
            } catch (RuntimeException e) {
                if (api != null) {
                    api.logging().logToError("[yuc] 读取历史数据失败：" + e.getMessage());
                }
                all = new ArrayList<>();
            }
            if (!all.isEmpty()) {
                loaded = true;
                adopt(all);
            }
        }
        if (!loaded) {
            // 库里空的：把目录里现有的 域名_端口.json 读回来。
            // 不这么做的话，升级后的第一次落盘会把老文件整份覆盖掉。
            List<Endpoint> legacy = TemplateImport.loadDir(dir);
            if (!legacy.isEmpty()) {
                backupLegacy(dir); // 先留一份原件，重建有偏差时还能找回
                adopt(legacy);
                for (String dk : new ArrayList<>(domains.keySet())) {
                    flush(dk); // 顺手入库，下次启动直接走数据库
                }
                if (api != null) {
                    api.logging().logToOutput("[yuc] 已从目录导入 " + legacy.size() + " 个历史接口：" + dir);
                }
            }
        }
    }

    /** 把目录里的 json 原样复制到 backup-时间戳/，只留一次。 */
    private void backupLegacy(File from) {
        File[] files = from.listFiles((d, name) -> name.toLowerCase().endsWith(".json"));
        if (files == null || files.length == 0) {
            return;
        }
        String stamp = new java.text.SimpleDateFormat("yyyyMMdd-HHmmss").format(new java.util.Date());
        File to = new File(from, "backup-" + stamp);
        if (!to.mkdirs()) {
            return;
        }
        for (File f : files) {
            try {
                Files.copy(f.toPath(), new File(to, f.getName()).toPath(),
                        StandardCopyOption.REPLACE_EXISTING);
            } catch (IOException e) {
                if (api != null) {
                    api.logging().logToError("[yuc] 备份 " + f.getName() + " 失败：" + e.getMessage());
                }
            }
        }
        if (api != null) {
            api.logging().logToOutput("[yuc] 老数据已备份到 " + to.getAbsolutePath());
        }
    }

    private void adopt(List<Endpoint> list) {
        synchronized (lock) {
            domains.clear();
            for (Endpoint ep : list) {
                Domain dom = domains.get(ep.domainKey());
                if (dom == null) {
                    dom = new Domain(ep.scheme, ep.host, ep.port);
                    domains.put(ep.domainKey(), dom);
                }
                Group g = dom.items.get(ep.key);
                if (g == null) {
                    g = new Group(ep.key);
                    dom.items.put(ep.key, g);
                }
                g.put(ep);
            }
            for (Domain d : domains.values()) {
                d.link();
            }
        }
    }


    // ------------------------------------------------------------ 采集开关

    public boolean isRecording() {
        return recording;
    }

    public void setRecording(boolean on) {
        this.recording = on;
        savePref("recording", on ? "1" : "0");
    }

    /** 当前勾选的采集来源；空集表示全部。返回只读快照，改它不会影响存储。 */
    public java.util.Set<String> toolFilter() {
        return toolFilter;
    }

    /**
     * 勾选要采集的来源。传空集合 = 全部。
     * <p>
     * 老版本存的是单选字符串（{@code 全部} / {@code 仅 Proxy}），
     * {@link #parseToolFilter} 会把它们翻译成集合，升级的人不用重新勾一遍。
     */
    public void setToolFilter(java.util.Collection<String> tools) {
        java.util.Set<String> next = new java.util.LinkedHashSet<>();
        if (tools != null) {
            for (String t : tools) {
                if (t != null && !t.isEmpty() && !"全部".equals(t)) {
                    next.add(t);
                }
            }
        }
        this.toolFilter = java.util.Collections.unmodifiableSet(next);
        savePref("tool", String.join(",", next));
    }

    /** {@code ""}/{@code 全部} → 空集；{@code 仅 Proxy} → {Proxy}；{@code Proxy,Repeater} → 两个。 */
    public static java.util.Set<String> parseToolFilter(String raw) {
        java.util.Set<String> out = new java.util.LinkedHashSet<>();
        if (raw == null) {
            return java.util.Set.of();
        }
        String s = raw.trim();
        if (s.isEmpty() || s.startsWith("全部")) {
            return java.util.Set.of();
        }
        if (s.startsWith("仅")) {
            String one = s.substring(1).trim();
            if (!one.isEmpty()) {
                out.add(one);
            }
            return java.util.Collections.unmodifiableSet(out);
        }
        for (String p : s.split("[,，\\s]+")) {
            if (!p.isEmpty()) {
                out.add(p);
            }
        }
        return out.isEmpty() ? java.util.Set.of() : java.util.Collections.unmodifiableSet(out);
    }

    /** 当前记录哪些内容类型；永远不会是空集（至少 JSON）。 */
    public java.util.Set<String> recordTypes() {
        return recordTypes;
    }

    /**
     * 勾选要记录的内容类型（JSON / HTML）。
     * <p>
     * 认不出的名字直接忽略；结果为空则退回「只 JSON」——不给"一条都不记"这种状态留入口。
     */
    public void setRecordTypes(java.util.Collection<String> types) {
        java.util.Set<String> next = new java.util.LinkedHashSet<>();
        if (types != null) {
            for (String t : types) {
                if (t == null) {
                    continue;
                }
                for (String known : Capture.TYPE_NAMES) {
                    if (known.equalsIgnoreCase(t.trim())) {
                        next.add(known);
                    }
                }
            }
        }
        if (next.isEmpty()) {
            next.add(Capture.TYPE_JSON);
        }
        this.recordTypes = java.util.Collections.unmodifiableSet(next);
        savePref("types", String.join(",", next));
    }

    /** {@code ""}（老版本没这一项）→ 只 JSON；{@code JSON,HTML} → 两个。 */
    public static java.util.Set<String> parseRecordTypes(String raw) {
        java.util.Set<String> out = new java.util.LinkedHashSet<>();
        if (raw != null) {
            for (String p : raw.split("[,，\\s]+")) {
                for (String known : Capture.TYPE_NAMES) {
                    if (!p.isEmpty() && known.equalsIgnoreCase(p.trim())) {
                        out.add(known);
                    }
                }
            }
        }
        if (out.isEmpty()) {
            out.add(Capture.TYPE_JSON); // 老配置 / 空值都按"只 JSON"处理
        }
        return java.util.Collections.unmodifiableSet(out);
    }

    public File dir() {
        return dir;
    }

    public void setDir(File d) {
        if (d == null || d.equals(dir)) {
            return;
        }
        flushAll(); // 旧目录的数据先落地，别丢
        Db old = db;
        db = null;
        if (old != null) {
            old.close();
        }
        synchronized (lock) {
            domains.clear();
        }
        this.dir = d;
        savePref("dir", d.getAbsolutePath());
        openDb();
        loadFromDb();
        fire(null);
    }

    // ------------------------------------------------------------ 写入

    /**
     * 收下一个样本。同一个接口按**响应长度**留档，一份长度一组参数：
     * <ul>
     *   <li><b>长度已经见过</b> → 直接丢。这条挡住了"同一个报错页反复抓、反复记"</li>
     *   <li><b>长度是新的，但请求参数名集合和已有档位一模一样</b> → 也丢。长度变了只是响应内容在抖
     *       （时间戳、traceId、列表条数），请求根本没变形，不值得再占一档</li>
     *   <li><b>比现有最长的还长</b> → 收下并成为主样本，参数随之更新（长度变长才更新参数值）</li>
     *   <li><b>是个没见过的更短长度</b> → 收下作为副档，<b>主样本不动</b>；
     *       但如果已经攒满 {@link #MAX_SAMPLES} 档，比最短的还短就不要了（那种多半是带随机串的报错页）</li>
     * </ul>
     * 主样本（最长那档）负责界面参数表和导出的模板；副档只在右键里按长度选用。
     * <p>
     * 「参数名集合」就是 {@link Params#requestShape}：查询 / Cookie / 请求体字段的 <b>名字</b>，
     * 排序去重、带位置前缀，不含值。所以 {@code page=1} 与 {@code page=2} 算同一种形状，
     * 而「少传一个参数」「多传一个 deptId」「未登录少了 sid」都算新形状——正好对应
     * 「正常 / 少参数全量 / 参数错 / 未登录」这几种要留档的形态。
     *
     * @return 是否真的更新了存储
     */
    public boolean add(Endpoint ep) {
        String dk = ep.domainKey();
        boolean changed = false;
        synchronized (lock) {
            Domain d = domains.get(dk);
            if (d == null) {
                d = new Domain(ep.scheme, ep.host, ep.port);
                domains.put(dk, d);
            }
            Group g = d.items.get(ep.key);
            if (g == null) {
                g = new Group(ep.key);
                d.items.put(ep.key, g);
            } else if (g.has(ep.responseLength)) {
                skipped++; // 同一长度：参数值不再刷新，保持第一次见到的样子
                return false;
            } else if (g.shapeTaken(ep)) {
                skipped++; // 新长度但请求形状没变：响应抖动，不占新档
                return false;
            } else if (g.size() >= MAX_SAMPLES) {
                if (ep.responseLength < g.shortest()) {
                    skipped++;
                    return false;
                }
                g.evictOldestSecondary();
            }
            g.put(ep);
            g.link();
            changed = true;
        }
        if (changed) {
            scheduleWrite(dk);
            fire(dk);
        }
        return changed;
    }

    public void addListener(Listener l) {
        listeners.add(l);
    }

    private void fire(String dk) {
        for (Listener l : listeners) {
            try {
                l.onChanged(dk);
            } catch (RuntimeException ignored) {
                // UI 出问题不能影响抓包
            }
        }
    }

    private void scheduleWrite(String dk) {
        synchronized (lock) {
            ScheduledFuture<?> old = pending.remove(dk);
            if (old != null) {
                old.cancel(false);
            }
            pending.put(dk, writer.schedule(() -> flush(dk), DEBOUNCE_MS, TimeUnit.MILLISECONDS));
        }
    }

    // ------------------------------------------------------------ 落盘

    public void flush(String domainKey) {
        String scheme;
        String host;
        int port;
        List<Endpoint> eps;
        List<Group> groups;
        synchronized (lock) {
            Domain d = domains.get(domainKey);
            if (d == null) {
                return;
            }
            scheme = d.scheme;
            host = d.host;
            port = d.port;
            eps = d.snapshot();
            groups = d.groups();
            pending.remove(domainKey);
        }
        write(scheme, host, port, eps);
        saveToDb(domainKey, groups);
    }

    private void saveToDb(String domainKey, List<Group> groups) {
        Db d = db;
        if (d == null) {
            return;
        }
        try {
            d.saveDomain(domainKey, groups, settings.maxResponseFields());
        } catch (RuntimeException e) {
            if (api != null) {
                api.logging().logToError("[yuc] 写入数据库失败 " + domainKey + " —— " + e.getMessage());
            }
        }
    }

    public void flushAll() {
        List<String> keys;
        synchronized (lock) {
            keys = new ArrayList<>(domains.keySet());
        }
        for (String k : keys) {
            flush(k);
        }
    }

    private void write(String scheme, String host, int port, List<Endpoint> eps) {
        try {
            File directory = dir;
            if (!directory.exists() && !directory.mkdirs()) {
                throw new IOException("无法创建目录 " + directory);
            }
            String json = MiniJson.pretty(TemplateBuilder.domainDoc(scheme, host, port, eps));
            Path target = new File(directory, TemplateBuilder.fileName(host, port)).toPath();
            Path tmp = target.resolveSibling(target.getFileName() + ".tmp");
            Files.writeString(tmp, json, StandardCharsets.UTF_8);
            try {
                Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING);
            }
        } catch (IOException | RuntimeException e) {
            if (api != null) {
                api.logging().logToError("[yuc] 写文件失败 " + host + ":" + port + " —— " + e);
            }
        }
    }

    // ------------------------------------------------------------ 查询

    public List<Domain> domains() {
        synchronized (lock) {
            return new ArrayList<>(domains.values());
        }
    }

    public Domain domain(String key) {
        synchronized (lock) {
            return domains.get(key);
        }
    }

    public List<Endpoint> endpoints(String domainKey) {
        synchronized (lock) {
            Domain d = domains.get(domainKey);
            return d == null ? new ArrayList<>() : d.snapshot();
        }
    }

    public int endpointCount() {
        synchronized (lock) {
            int n = 0;
            for (Domain d : domains.values()) {
                n += d.items.size();
            }
            return n;
        }
    }

    /** 所有长度档加起来的样本条数（一个接口有多档时会大于接口数）。 */
    public int sampleCount() {
        synchronized (lock) {
            int n = 0;
            for (Domain d : domains.values()) {
                n += d.sampleCount();
            }
            return n;
        }
    }

    public long skipped() {
        synchronized (lock) {
            return skipped;
        }
    }

    public void clearDomain(String domainKey) {
        String scheme;
        String host;
        int port;
        synchronized (lock) {
            Domain d = domains.get(domainKey);
            if (d == null) {
                return;
            }
            d.items.clear();
            scheme = d.scheme;
            host = d.host;
            port = d.port;
        }
        write(scheme, host, port, new ArrayList<>());
        Db d = db;
        if (d != null) {
            try {
                d.deleteDomain(domainKey);
            } catch (RuntimeException e) {
                if (api != null) {
                    api.logging().logToError("[yuc] 删除数据库记录失败：" + e.getMessage());
                }
            }
        }
        fire(domainKey);
    }

    /**
     * 彻底删掉一个域名：内存、SQLite、以及它那份 {@code 域名_端口.json} 一起清掉。
     * <p>
     * 和 {@link #clearDomain} 的区别：那个只清接口、把节点留着（界面上变成 0 条），
     * 这个是连节点带文件一起消失——用户右键「删除该域名」时要的就是这个效果。
     */
    public boolean removeDomain(String domainKey) {
        Domain d;
        synchronized (lock) {
            d = domains.remove(domainKey);
            ScheduledFuture<?> f = pending.remove(domainKey);
            if (f != null) {
                f.cancel(false);
            }
        }
        if (d == null) {
            return false;
        }
        File json = new File(dir, TemplateBuilder.fileName(d.host, d.port));
        try {
            Files.deleteIfExists(json.toPath());
        } catch (IOException e) {
            if (api != null) {
                api.logging().logToError("[yuc] 删除 " + json.getName() + " 失败：" + e.getMessage());
            }
        }
        Db dbRef = db;
        if (dbRef != null) {
            try {
                dbRef.deleteDomain(domainKey);
            } catch (RuntimeException e) {
                if (api != null) {
                    api.logging().logToError("[yuc] 删除数据库记录失败：" + e.getMessage());
                }
            }
        }
        marks.forgetDomain(domainKey); // 域名都没了，它的路径颜色也没意义了
        fire(domainKey);
        return true;
    }

    /** 这个域名下有没有这个接口（导入时用来判重）。 */
    public boolean has(String domainKey, String endpointKey) {
        synchronized (lock) {
            Domain d = domains.get(domainKey);
            return d != null && d.items.containsKey(endpointKey);
        }
    }

    /**
     * 删掉指定的若干接口，然后重写该域名的 json 与库。
     * <p>
     * 重写走的是整域名重写，所以 json 里那个 item 会跟着消失——不需要另外维护"删了哪一条"。
     * 如果一个域名被删空了，顺手把整个域名和文件一起收掉，免得留个 0 条的空节点。
     *
     * @return 真正删掉的接口数（一个长度档组算一个接口）
     */
    public int removeEndpoints(java.util.Collection<Endpoint> eps) {
        java.util.Set<String> touched = new java.util.LinkedHashSet<>();
        int removed = 0;
        synchronized (lock) {
            for (Endpoint ep : eps) {
                Domain d = domains.get(ep.domainKey());
                if (d == null) {
                    continue;
                }
                if (d.items.remove(ep.key) != null) {
                    removed++;
                    touched.add(ep.domainKey());
                }
            }
        }
        for (String dk : touched) {
            boolean empty;
            synchronized (lock) {
                Domain d = domains.get(dk);
                empty = d == null || d.items.isEmpty();
            }
            if (empty) {
                removeDomain(dk);
            } else {
                flush(dk);
            }
        }
        if (!touched.isEmpty()) {
            fire(null);
        }
        return removed;
    }

    /**
     * 导入模板里的接口（界面「导入 JSON」用）。
     * <p>
     * 已存在的（同方法 + 同路径 + 同 query 参数名集合）直接跳过：模板里的样本没有响应，
     * 长度是 0，混进真实样本里会白占一个档位、还会让界面显示成「0 等2档」。
     *
     * @return 真正新加进来的接口数
     */
    public int importEndpoints(List<Endpoint> list) {
        int added = 0;
        for (Endpoint ep : list) {
            if (!has(ep.domainKey(), ep.key) && add(ep)) {
                added++;
            }
        }
        return added;
    }

    public void clearAll() {
        List<Domain> all;
        synchronized (lock) {
            all = new ArrayList<>(domains.values());
            domains.clear();
        }
        for (Domain d : all) {
            write(d.scheme, d.host, d.port, new ArrayList<>());
        }
        Db d = db;
        if (d != null) {
            try {
                d.deleteAll();
            } catch (RuntimeException e) {
                if (api != null) {
                    api.logging().logToError("[yuc] 清空数据库失败：" + e.getMessage());
                }
            }
        }
        marks.clear();
        fire(null);
    }

    public void shutdown() {
        flushAll();
        Db d = db;
        db = null;
        if (d != null) {
            d.close();
        }
        writer.shutdownNow();
    }

    // ------------------------------------------------------------ 设置持久化

    private String pref(String key, String fallback) {
        try {
            String v = api.persistence().preferences().getString("yuc." + key);
            return v == null || v.isEmpty() ? fallback : v;
        } catch (RuntimeException e) {
            return fallback;
        }
    }

    private void savePref(String key, String value) {
        try {
            api.persistence().preferences().setString("yuc." + key, value);
        } catch (RuntimeException ignored) {
            // 临时工程模式下没有项目持久化，忽略即可
        }
    }

    /** 一个域名端口下的所有接口。 */
    public static final class Domain {
        public final String scheme;
        public final String host;
        public final int port;
        public final String key;
        final Map<String, Group> items = new LinkedHashMap<>();

        Domain(String scheme, String host, int port) {
            this.scheme = scheme;
            this.host = host;
            this.port = port;
            this.key = host + ":" + port;
        }

        public String label() {
            return host + ":" + port;
        }

        /** 接口个数（不是样本个数）。 */
        public int size() {
            return items.size();
        }

        /** 所有长度档加起来有多少条样本。 */
        public int sampleCount() {
            int n = 0;
            for (Group g : items.values()) {
                n += g.size();
            }
            return n;
        }

        /** 每个接口的主样本（最长那档）——界面、模板导出都只认它。 */
        List<Endpoint> snapshot() {
            List<Endpoint> out = new ArrayList<>(items.size());
            for (Group g : items.values()) {
                Endpoint p = g.primary();
                if (p != null) {
                    out.add(p);
                }
            }
            return out;
        }

        /** 全部长度档，落库用。 */
        List<Group> groups() {
            return new ArrayList<>(items.values());
        }

        void link() {
            for (Group g : items.values()) {
                g.link();
            }
        }
    }

    /**
     * 同一接口按响应长度攒下的若干样本。
     * <p>
     * 为什么按长度分档：同一个接口，少传一个参数可能返回"全量数据"，多传一个参数可能返回报错页，
     * 两者长度不同、参数集也不同。只留一条必然丢信息；全留又会互相覆盖。
     * <p>
     * 但只有<b>参数集真的变了</b>才算另一档（{@link #shapeTaken}）：同一套参数反复回包、
     * 长度被时间戳顶得上下浮动，那还是同一条请求，不该占档位。
     */
    public static final class Group {
        public final String key;
        /** 长度 → 样本，天然按长度升序；最后一个就是主样本。 */
        private final java.util.TreeMap<Long, Endpoint> samples = new java.util.TreeMap<>();

        Group(String key) {
            this.key = key;
        }

        public int size() {
            return samples.size();
        }

        public boolean has(long length) {
            return samples.containsKey(length);
        }

        /**
         * 这个请求形状是不是已经被某一档占着了。
         * <p>
         * 只跟「真抓到过响应」的档位比：长度 0 的是模板导入的空壳，让它参与会把真样本挡掉。
         * 形状认不出来的（原始报文体）一律算「没占」——宁可多记一档，也别把内容丢了。
         */
        boolean shapeTaken(Endpoint ep) {
            String shape = ep.requestShape();
            if (shape == null || ep.responseLength <= 0) {
                return false;
            }
            for (Endpoint e : samples.values()) {
                if (e.responseLength > 0 && shape.equals(e.requestShape())) {
                    return true;
                }
            }
            return false;
        }

        public long shortest() {
            return samples.isEmpty() ? -1 : samples.firstKey();
        }

        /** 最长那档：界面参数表、模板导出、默认「发送到 Repeater」都用它。 */
        public Endpoint primary() {
            return samples.isEmpty() ? null : samples.lastEntry().getValue();
        }

        /** 所有档位，按长度升序（最后一档是主样本）。 */
        public List<Endpoint> all() {
            return new ArrayList<>(samples.values());
        }

        void put(Endpoint ep) {
            samples.put(ep.responseLength, ep);
        }

        /** 满了就淘汰"最旧的一条副档"，绝不动主样本。 */
        void evictOldestSecondary() {
            if (samples.size() < 2) {
                return;
            }
            Long victim = null;
            long oldest = Long.MAX_VALUE;
            for (Map.Entry<Long, Endpoint> e : samples.entrySet()) {
                if (e.getKey().equals(samples.lastKey())) {
                    continue; // 主样本不参与淘汰
                }
                // 用严格小于：时间戳撞在一起时留下最小的那个（最短的一般信息最少）
                if (e.getValue().lastSeen < oldest) {
                    oldest = e.getValue().lastSeen;
                    victim = e.getKey();
                }
            }
            if (victim != null) {
                samples.remove(victim);
            }
        }

        /** 把整组挂到每个样本上，UI 右键按长度选的时候直接看 {@link Endpoint#samples()}。 */
        void link() {
            List<Endpoint> all = all();
            for (Endpoint e : all) {
                e.setSamples(all);
            }
        }
    }
}
