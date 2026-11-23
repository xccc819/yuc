package yuc;

import burp.api.montoya.MontoyaApi;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JDialog;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JMenu;
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JSpinner;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.JTree;
import javax.swing.ListSelectionModel;
import javax.swing.SpinnerNumberModel;
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import javax.swing.event.TreeExpansionEvent;
import javax.swing.event.TreeExpansionListener;
import javax.swing.table.DefaultTableModel;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreePath;
import javax.swing.tree.TreeSelectionModel;
import java.awt.BorderLayout;
import java.awt.Desktop;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridLayout;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 主界面：左边域名，右边「路径 + 参数」两张表。
 * <p>
 * 交互约定：点域名 → 看这个域名下的全部接口；点某一行路径 → 参数表自动收窄到这个接口；
 * 路径可以按「从左/从右留 N 段」截断显示（只影响显示，不影响落盘与还原）；
 * 右键能把这条请求还原到 Repeater，也能删掉这条路径（json 里对应 item 一起删）。
 */
public final class YucPanel extends JPanel {

    private final MontoyaApi api;
    private final EndpointStore store;

    private final JCheckBox recordBox = new JCheckBox("开始采集");
    /**
     * 采集来源改多选：一个站常常在 Proxy 和 Repeater 里各跑一半，单选下拉只能二选一。
     * 空集 = 全部来源（和参数来源同一套语义）。
     */
    private final Set<String> toolSources = new LinkedHashSet<>();
    private final JButton toolSourceButton = new JButton("来源：全部");
    private final JButton typeButton = new JButton("类型：JSON");
    private final JButton importButton = new JButton("导入历史");
    private final JButton importJsonButton = new JButton("导入 JSON…");
    private final JButton headerButton = new JButton("请求头…");
    private final JButton settingsButton = new JButton("设置…");
    private final JTextField dirField = new JTextField(22);
    private final JLabel statsLabel = new JLabel("域名 0 · 接口 0");

    private final HeaderProfile headers;

    private final JTextField domainSearch = new JTextField(14);
    private final DefaultMutableTreeNode rootNode = new DefaultMutableTreeNode("全部");
    private final DefaultTreeModel treeModel = new DefaultTreeModel(rootNode);
    private final JTree domainTree = new JTree(treeModel);
    /** 用户手动点开过的分组（根域 / IP 段）。默认全部收起，刷新时按它恢复。 */
    private final Set<String> expandedGroups = new HashSet<>();
    /** 我们自己在重建树，这时收到的展开/收起事件不算用户操作。 */
    private boolean rebuilding;

    private final JComboBox<String> pathMode = new JComboBox<>(new String[]{"完整路径", "从左往右", "从右往左"});
    private final JSpinner pathDepth = new JSpinner(new SpinnerNumberModel(2, 1, 9, 1));
    private final JTextField pathFilter = new JTextField(12);
    private final JCheckBox pathIgnoreCase = new JCheckBox("忽略大小写", true);
    private final JCheckBox pathInvert = new JCheckBox("反向");
    private final JCheckBox pathRegex = new JCheckBox("正则");
    private final JButton pathAdvancedButton = new JButton("高级");
    /** 高级搜索的条件（列 + 关系 + 值）；空表示没加高级条件。 */
    private List<SearchRule> pathRules = new ArrayList<>();
    /** 有色行的排序方式。**只有「高级」弹框里能改**——表头点击排序是 JTable 自带的，颜色不是一列。 */
    private ColorSort pathSort = ColorSort.DEFAULT;
    private final JLabel pathCount = new JLabel();

    private final DefaultTableModel pathModel = tableModel(
            new Object[]{"路径", "方法", "参数", "响应字节", "状态", "来源"});
    private final List<PathRow> visible = new ArrayList<>();
    private final JTable pathTable = new JTable(pathModel) {
        @Override
        public String getToolTipText(MouseEvent e) {
            int row = rowAtPoint(e.getPoint());
            PathRow r = row < 0 ? null : rowAt(row);
            if (r == null) {
                return null;
            }
            String tip = r.ep.url;
            if (r.ep.sampleCount() > 1) {
                StringBuilder sb = new StringBuilder(tip).append("   （");
                List<Endpoint> samples = r.ep.samples();
                for (int i = 0; i < samples.size(); i++) {
                    if (i > 0) {
                        sb.append(" / ");
                    }
                    sb.append(samples.get(i).responseLength);
                }
                tip = sb.append(" 字节，右键选长度发到 Repeater）").toString();
            }
            return tip;
        }
    };

    private final JTextField paramFilter = new JTextField(12);
    private final JCheckBox paramIgnoreCase = new JCheckBox("忽略大小写", true);
    private final JCheckBox paramInvert = new JCheckBox("反向");
    private final JCheckBox paramRegex = new JCheckBox("正则");
    private final JButton paramAdvancedButton = new JButton("高级");
    private List<SearchRule> paramRules = new ArrayList<>();
    private ColorSort paramSort = ColorSort.DEFAULT;
    /** 参数来源的可选项，与 ParamStat.where 的取值一一对应。 */
    private static final String[] PARAM_SOURCES = {"查询", "Cookie", "请求头", "请求体", "表单", "multipart", "响应"};
    /** 多选来源筛选；空集表示不筛（全部来源）。 */
    private final Set<String> paramSources = new HashSet<>();
    private final JButton paramSourceButton = new JButton("来源：全部");
    private final JLabel paramCount = new JLabel();
    private final DefaultTableModel paramModel = tableModel(
            new Object[]{"参数", "位置", "接口数", "示例值"});
    private final List<Params.ParamStat> paramRows = new ArrayList<>();
    private final JTable paramTable = new JTable(paramModel) {
        @Override
        public String getToolTipText(MouseEvent e) {
            int row = rowAtPoint(e.getPoint());
            int col = columnAtPoint(e.getPoint());
            if (row < 0 || col != 0) {
                return null;
            }
            int modelRow = convertRowIndexToModel(row);
            if (modelRow < 0 || modelRow >= paramRows.size()) {
                return null;
            }
            Params.ParamStat st = paramRows.get(modelRow);
            return st.fullPath.equals(st.name)
                    ? st.name
                    : st.fullPath + "   （出现在 " + st.endpoints + " 个接口里）";
        }
    };

    private final Timer refreshTimer;

    private String selectedDomain;
    /** 选中了根域分组节点（demo.com.cn / 10.0.0.0/24）时为分组名；与 selectedDomain 互斥。 */
    private String selectedGroup;
    /** 导入历史是否正在跑（防重复点击）。 */
    private boolean importing;
    /** 由「参数 → 只看用到该参数的接口」产生的路径约束；null 表示没有。 */
    private Set<String> paramScopeKeys;
    private String paramScopeName;
    private List<Endpoint> endpoints = new ArrayList<>();
    private List<Params.ParamStat> statsCache = List.of();

    public YucPanel(MontoyaApi api, EndpointStore store) {
        this.api = api;
        this.store = store;
        this.headers = new HeaderProfile(api);

        setLayout(new BorderLayout());
        add(buildHeader(), BorderLayout.NORTH);
        add(buildBody(), BorderLayout.CENTER);

        refreshTimer = new Timer(600, e -> refreshAll());
        refreshTimer.setRepeats(false);

        store.addListener(domainKey -> SwingUtilities.invokeLater(refreshTimer::restart));

        recordBox.setSelected(store.isRecording());
        recordBox.addActionListener(e -> {
            store.setRecording(recordBox.isSelected());
            updateStats();
        });
        toolSources.addAll(store.toolFilter());
        dirField.setText(store.dir().getAbsolutePath());

        pathDepth.setEnabled(false);
        updateHeaderButton();
        updateToolSourceButton();
        updateTypeButton();
        updateParamSourceButton();
        updateAdvancedButtons();
        refreshAll();
    }

    // ---------------------------------------------------------------- 布局

    private JPanel buildHeader() {
        JPanel header = new JPanel();
        header.setLayout(new BoxLayout(header, BoxLayout.Y_AXIS));
        header.setBorder(BorderFactory.createEmptyBorder(8, 10, 6, 10));

        JPanel titleRow = new JPanel(new BorderLayout());
        JLabel title = new JLabel(YucExtension.NAME + " v" + YucExtension.VERSION
                + " — 接口采集 / 模板导出");
        title.setFont(title.getFont().deriveFont(Font.BOLD, title.getFont().getSize2D() + 2f));
        titleRow.add(title, BorderLayout.WEST);
        statsLabel.setForeground(muted());
        titleRow.add(statsLabel, BorderLayout.EAST);
        header.add(titleRow);
        header.add(Box.createVerticalStrut(6));

        // 拆两行：一行放采集开关和目录，一行放各种动作按钮。
        // 原来挤在一行里，窗口一窄后面的按钮就被裁掉（FlowLayout 不自动换行）
        JPanel row1 = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 3));
        recordBox.setToolTipText("勾选后才开始记录：不勾选时插件对流量完全只读不记");
        row1.add(recordBox);
        toolSourceButton.setToolTipText("勾选要采集哪些模块发出的请求（可多选，都不勾 = 全部）");
        toolSourceButton.addActionListener(e -> editToolSources());
        row1.add(toolSourceButton);
        typeButton.setToolTipText("勾选要记录哪些响应类型（JSON / HTML）；HTML 默认不记，否则接口表会被页面淹掉");
        typeButton.addActionListener(e -> editRecordTypes());
        row1.add(typeButton);
        row1.add(new JLabel("存储目录"));
        row1.add(dirField);
        JButton browse = new JButton("浏览…");
        browse.addActionListener(e -> chooseDir());
        row1.add(browse);
        JButton open = new JButton("打开目录");
        open.addActionListener(e -> openDir());
        row1.add(open);
        header.add(row1);

        JPanel row2 = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 3));
        importButton.setToolTipText("主动把 Burp Proxy 历史（Logger 里 tool=Proxy 的记录）按同一套规则补捞一遍；"
                + "与「开始采集」开关无关，重复点击安全（同接口只按长度留档）");
        importButton.addActionListener(e -> startImportHistory());
        row2.add(importButton);
        importJsonButton.setToolTipText("把 v3-lite 模板导入进来：可以选文件（量大）或直接粘贴（量少）");
        importJsonButton.addActionListener(e -> importJsonDialog());
        row2.add(importJsonButton);
        headerButton.setToolTipText("配置还原时统一套用的请求头（Authorization / Cookie 等），支持整段粘贴 Repeater 报文自动识别");
        headerButton.addActionListener(e -> editHeaders());
        row2.add(headerButton);
        settingsButton.setToolTipText(store.settings().summary());
        settingsButton.addActionListener(e -> editSettings());
        row2.add(settingsButton);
        JButton save = new JButton("立即保存");
        save.setToolTipText("把所有域名立刻写盘（平时是自动防抖保存）");
        save.addActionListener(e -> {
            store.flushAll();
            info("已保存到 " + store.dir().getAbsolutePath());
        });
        row2.add(save);
        header.add(row2);
        return header;
    }

    private JSplitPane buildBody() {
        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, buildDomainPane(), buildTablesPane());
        split.setResizeWeight(0.2);
        split.setBorder(BorderFactory.createEmptyBorder(0, 8, 8, 8));
        return split;
    }

    private JPanel buildDomainPane() {
        JPanel panel = new JPanel(new BorderLayout(0, 4));

        JPanel top = new JPanel(new BorderLayout(0, 4));
        JLabel label = new JLabel("域名");
        label.setBorder(BorderFactory.createEmptyBorder(3, 2, 0, 0));
        top.add(label, BorderLayout.NORTH);

        domainSearch.setToolTipText("按域名 / IP 过滤左侧的树，只留下命中的（父级自动保留、自动展开）");
        domainSearch.getDocument().addDocumentListener(new SimpleDoc(this::rebuildTree));
        top.add(domainSearch, BorderLayout.CENTER);
        panel.add(top, BorderLayout.NORTH);

        domainTree.setRootVisible(true);
        domainTree.setShowsRootHandles(true);
        domainTree.getSelectionModel().setSelectionMode(TreeSelectionModel.SINGLE_TREE_SELECTION);
        domainTree.addTreeSelectionListener(e -> {
            TreePath path = domainTree.getSelectionPath();
            Object node = path == null ? null : ((DefaultMutableTreeNode) path.getLastPathComponent()).getUserObject();
            // 三种节点：全部（两个都 null）/ 根域分组 / 单个 host:port
            selectedDomain = node instanceof DomainNode ? ((DomainNode) node).key : null;
            selectedGroup = node instanceof GroupNode ? ((GroupNode) node).name : null;
            reloadDomain();
        });
        // 记住用户点开过哪些分组：数据一刷新就重建树，不记的话刚点开的那组会自己收回去
        domainTree.addTreeExpansionListener(new TreeExpansionListener() {
            @Override
            public void treeExpanded(TreeExpansionEvent event) {
                trackGroup(event.getPath(), true);
            }

            @Override
            public void treeCollapsed(TreeExpansionEvent event) {
                trackGroup(event.getPath(), false);
            }
        });
        domainTree.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                treePopup(e);
            }

            @Override
            public void mouseReleased(MouseEvent e) {
                treePopup(e);
            }
        });
        JScrollPane scroll = new JScrollPane(domainTree);
        scroll.setPreferredSize(new Dimension(230, 400));
        panel.add(scroll, BorderLayout.CENTER);
        return panel;
    }

    private JSplitPane buildTablesPane() {
        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, buildPathPane(), buildParamPane());
        split.setResizeWeight(0.55);
        return split;
    }

    private JPanel buildPathPane() {
        JPanel panel = new JPanel(new BorderLayout(0, 4));

        // 挤成一行：两行那种排版看着松散，一半高度都浪费在留白上
        JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 3));
        bar.add(new JLabel("展示"));
        pathMode.setToolTipText("只看路径的前 N 段 / 后 N 段，只影响显示，不影响落盘和还原");
        pathMode.addActionListener(e -> {
            pathDepth.setEnabled(pathMode.getSelectedIndex() != Urls.PATH_FULL);
            applyFilter();
        });
        bar.add(pathMode);
        bar.add(pathDepth);
        bar.add(new JLabel("段"));
        bar.add(new JLabel("过滤"));
        pathFilter.setToolTipText("对完整路径 + 方法做匹配；勾「正则」后按正则表达式匹配");
        pathFilter.getDocument().addDocumentListener(new SimpleDoc(this::applyFilter));
        pathFilter.addActionListener(e -> applyFilter());
        bar.add(pathFilter);
        pathIgnoreCase.setToolTipText("匹配时不区分大小写");
        pathIgnoreCase.addActionListener(e -> applyFilter());
        bar.add(pathIgnoreCase);
        pathInvert.setToolTipText("反过来：只保留**不**匹配的行");
        pathInvert.addActionListener(e -> applyFilter());
        bar.add(pathInvert);
        pathRegex.setToolTipText("把过滤框里的内容当正则表达式（写错不报错，只是匹配不到）");
        pathRegex.addActionListener(e -> applyFilter());
        bar.add(pathRegex);
        pathAdvancedButton.addActionListener(e -> editAdvanced(true));
        bar.add(pathAdvancedButton);
        JButton reset = new JButton("重置");
        reset.setToolTipText("清掉过滤条件（含高级搜索），回到筛选前（不影响展示方式）");
        reset.addActionListener(e -> resetPathFilters());
        bar.add(reset);
        JButton copyPaths = new JButton("复制路径");
        copyPaths.setToolTipText("复制当前可见的路径（按当前展示方式）");
        copyPaths.addActionListener(e -> copy(joinColumn(pathTable, 0)));
        bar.add(copyPaths);
        JButton copyUrls = new JButton("复制 URL");
        copyUrls.addActionListener(e -> copy(joinUrls()));
        bar.add(copyUrls);
        bar.add(pathCount);
        panel.add(bar, BorderLayout.NORTH);

        pathTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        pathTable.setAutoCreateRowSorter(true);
        pathTable.getColumnModel().getColumn(0).setPreferredWidth(360);
        pathTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                refreshParams();
            }
        });
        pathTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                maybePopup(e, pathTable, YucPanel.this::pathPopup);
            }

            @Override
            public void mouseReleased(MouseEvent e) {
                maybePopup(e, pathTable, YucPanel.this::pathPopup);
            }

            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2 && SwingUtilities.isLeftMouseButton(e)) {
                    showDetail();
                }
            }
        });
        panel.add(new JScrollPane(pathTable), BorderLayout.CENTER);
        paintRows(pathTable, modelRow ->
                modelRow >= 0 && modelRow < visible.size() ? pathColor(visible.get(modelRow).ep) : 0);
        return panel;
    }

    private JPanel buildParamPane() {
        JPanel panel = new JPanel(new BorderLayout(0, 4));

        JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 3));
        bar.add(new JLabel("参数"));
        paramSourceButton.setToolTipText("按参数来源多选筛选（可同时勾选查询 + 请求体等）");
        paramSourceButton.addActionListener(e -> editParamSources());
        bar.add(paramSourceButton);
        bar.add(new JLabel("过滤"));
        paramFilter.setToolTipText("对参数名 / 完整路径 / 位置 / 示例值做匹配；勾「正则」后按正则匹配");
        paramFilter.getDocument().addDocumentListener(new SimpleDoc(this::refreshParams));
        bar.add(paramFilter);
        paramIgnoreCase.setToolTipText("匹配时不区分大小写");
        paramIgnoreCase.addActionListener(e -> refreshParams());
        bar.add(paramIgnoreCase);
        paramInvert.setToolTipText("反过来：只保留**不**匹配的行");
        paramInvert.addActionListener(e -> refreshParams());
        bar.add(paramInvert);
        paramRegex.setToolTipText("把过滤框里的内容当正则表达式（写错不报错，只是匹配不到）");
        paramRegex.addActionListener(e -> refreshParams());
        bar.add(paramRegex);
        paramAdvancedButton.addActionListener(e -> editAdvanced(false));
        bar.add(paramAdvancedButton);
        JButton reset = new JButton("重置");
        reset.setToolTipText("清掉参数过滤（含高级搜索与来源筛选），回到筛选前");
        reset.addActionListener(e -> resetParamFilters());
        bar.add(reset);
        JButton copyParams = new JButton("复制参数");
        copyParams.setToolTipText("复制当前可见的参数名（已去重，每行一个）");
        copyParams.addActionListener(e -> copy(joinColumn(paramTable, 0)));
        bar.add(copyParams);
        bar.add(paramCount);
        panel.add(bar, BorderLayout.NORTH);

        paramTable.setAutoCreateRowSorter(true);
        paramTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        paramTable.getColumnModel().getColumn(0).setPreferredWidth(240);
        paramTable.getColumnModel().getColumn(3).setPreferredWidth(320);
        paramTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                maybePopup(e, paramTable, YucPanel.this::paramPopup);
            }

            @Override
            public void mouseReleased(MouseEvent e) {
                maybePopup(e, paramTable, YucPanel.this::paramPopup);
            }
        });
        panel.add(new JScrollPane(paramTable), BorderLayout.CENTER);
        paintRows(paramTable, modelRow ->
                modelRow >= 0 && modelRow < paramRows.size() ? paramColor(paramRows.get(modelRow)) : 0);
        return panel;
    }

    // ---------------------------------------------------------------- 刷新

    private void refreshAll() {
        settingsButton.setToolTipText(store.settings().summary());
        rebuildTree();
        reloadDomain();
        updateStats();
    }

    /**
     * 重建左侧树：全部 → 根域（demo.com.cn）/ IP 段（10.0.0.0/24）→ host:port。
     * <p>
     * 按根域分组是因为一次测试里 demo.com.cn 下往往有十几台机器（h5 / api / mweb / admin），
     * 平铺成一层会淹没真正想找的那台。IP 按 /24 归拢同理：内网一次扫就是一大段。
     * <p>
     * 分组**默认收起**：域名多了以后全展开要滚半天。用户点开过的那几组会被记住
     * （{@link #expandedGroups}），数据刷新重建成同一副样子，不会自己收回去。
     */
    private void rebuildTree() {
        String keepDomain = selectedDomain;
        String keepGroup = selectedGroup;
        String q = domainSearch.getText().trim().toLowerCase();
        boolean searching = !q.isEmpty();

        rootNode.removeAllChildren();

        List<EndpointStore.Domain> all = store.domains();
        all.sort((a, b) -> a.label().compareTo(b.label()));

        // 根域 → 该组下的域名
        Map<String, List<EndpointStore.Domain>> groups = new LinkedHashMap<>();
        int total = 0;
        for (EndpointStore.Domain d : all) {
            total += d.size();
            if (searching && !d.label().toLowerCase().contains(q)) {
                continue;
            }
            groups.computeIfAbsent(Urls.rootDomain(d.host), k -> new ArrayList<>()).add(d);
        }

        int shown = 0;
        for (Map.Entry<String, List<EndpointStore.Domain>> e : groups.entrySet()) {
            List<EndpointStore.Domain> list = e.getValue();
            int count = 0;
            for (EndpointStore.Domain d : list) {
                count += d.size();
            }
            shown += count;

            DefaultMutableTreeNode group = new DefaultMutableTreeNode(
                    new GroupNode(e.getKey(), e.getKey() + "  (" + count + ")", count));
            for (EndpointStore.Domain d : list) {
                group.add(new DefaultMutableTreeNode(new DomainNode(d.key, d.label() + "  (" + d.size() + ")")));
            }
            rootNode.add(group);
        }

        rootNode.setUserObject("全部  (" + (searching ? shown : total) + ")");

        rebuilding = true;
        try {
            treeModel.reload();
            domainTree.expandRow(0);
            for (int i = 0; i < rootNode.getChildCount(); i++) {
                DefaultMutableTreeNode group = (DefaultMutableTreeNode) rootNode.getChildAt(i);
                Object o = group.getUserObject();
                // 搜索时全展开（不然搜到了也看不见），平时只展开用户点开过的
                if (searching || (o instanceof GroupNode && expandedGroups.contains(((GroupNode) o).name))) {
                    domainTree.expandPath(new TreePath(group.getPath()));
                }
            }
        } finally {
            rebuilding = false;
        }

        // 尽量保住原来的选中项；被搜索隐藏了就退回「全部」
        if (keepDomain != null && selectDomain(keepDomain)) {
            return;
        }
        if (keepGroup != null && selectGroup(keepGroup)) {
            return;
        }
        domainTree.setSelectionRow(0);
    }

    private void trackGroup(TreePath path, boolean open) {
        if (rebuilding || path == null) {
            return;
        }
        // 搜索时的展开是插件自动做的（不然搜到了也看不见），不算用户的选择，
        // 否则清空搜索以后所有分组都摊开，等于「默认收起」白做
        if (!domainSearch.getText().trim().isEmpty()) {
            return;
        }
        Object o = ((DefaultMutableTreeNode) path.getLastPathComponent()).getUserObject();
        if (o instanceof GroupNode) {
            if (open) {
                expandedGroups.add(((GroupNode) o).name);
            } else {
                expandedGroups.remove(((GroupNode) o).name);
            }
        }
    }

    private boolean selectDomain(String key) {
        for (int g = 0; g < rootNode.getChildCount(); g++) {
            DefaultMutableTreeNode group = (DefaultMutableTreeNode) rootNode.getChildAt(g);
            for (int i = 0; i < group.getChildCount(); i++) {
                DefaultMutableTreeNode child = (DefaultMutableTreeNode) group.getChildAt(i);
                if (child.getUserObject() instanceof DomainNode
                        && ((DomainNode) child.getUserObject()).key.equals(key)) {
                    domainTree.setSelectionPath(new TreePath(child.getPath()));
                    return true;
                }
            }
        }
        return false;
    }

    private boolean selectGroup(String name) {
        for (int g = 0; g < rootNode.getChildCount(); g++) {
            DefaultMutableTreeNode group = (DefaultMutableTreeNode) rootNode.getChildAt(g);
            if (group.getUserObject() instanceof GroupNode && ((GroupNode) group.getUserObject()).name.equals(name)) {
                domainTree.setSelectionPath(new TreePath(group.getPath()));
                return true;
            }
        }
        return false;
    }

    private void reloadDomain() {
        // 参数约束是「某个域名里的某些接口」，换域名就失效了
        paramScopeKeys = null;
        paramScopeName = null;
        if (selectedDomain != null) {
            endpoints = store.endpoints(selectedDomain);
        } else if (selectedGroup != null) {
            List<Endpoint> merged = new ArrayList<>();
            for (EndpointStore.Domain d : store.domains()) {
                if (Urls.rootDomain(d.host).equals(selectedGroup)) {
                    merged.addAll(store.endpoints(d.key));
                }
            }
            endpoints = merged;
        } else {
            List<Endpoint> all = new ArrayList<>();
            for (EndpointStore.Domain d : store.domains()) {
                all.addAll(store.endpoints(d.key));
            }
            endpoints = all;
        }
        statsCache = Params.stats(endpoints, HeaderPolicy.collect(endpoints),
                store.settings().maxResponseFields());
        applyFilter();
        refreshParams();
    }

    private void applyFilter() {
        int mode = pathMode.getSelectedIndex();
        int depth = ((Number) pathDepth.getValue()).intValue();
        String q = pathFilter.getText().trim();
        boolean ic = pathIgnoreCase.isSelected();
        boolean re = pathRegex.isSelected();
        boolean inv = pathInvert.isSelected();
        List<SearchRule> rules = pathRules;
        boolean active = !q.isEmpty() || !rules.isEmpty();

        pathModel.setRowCount(0);
        visible.clear();
        for (Endpoint ep : endpoints) {
            boolean hit = q.isEmpty() || TextFilter.contains(ep.path + " " + ep.method, q, ic, re);
            if (hit && !rules.isEmpty()) {
                hit = SearchRule.match(rules, pathRow(ep), ic);
            }
            if (active && inv == hit) {
                continue;
            }
            if (paramScopeKeys != null && !paramScopeKeys.contains(ep.key)) {
                continue;
            }
            visible.add(new PathRow(ep, ep.paramCount()));
        }
        // 标了颜色的行置顶（默认），或按颜色序号排。List.sort 是稳定排序，
        // 所以「同一档」内部仍然是域名 / 采集顺序，不会跳来跳去
        if (!visible.isEmpty()) {
            visible.sort((a, b) -> compareColor(pathColor(a.ep), pathColor(b.ep), pathSort));
        }
        for (PathRow r : visible) {
            pathModel.addRow(new Object[]{
                    Urls.displayPath(r.ep.path, mode, depth),
                    r.ep.method,
                    r.paramCount,
                    byteLabel(r.ep),
                    r.ep.status,
                    r.ep.tool});
        }
        pathCount.setText("可见 " + visible.size() + " / " + endpoints.size()
                + (rules.isEmpty() ? "" : " · 高级 " + rules.size())
                + (pathSort == ColorSort.DEFAULT ? "" : " · " + pathSort.shortLabel)
                + (paramScopeName == null ? "" : " · 参数 " + paramScopeName));
        pathCount.setForeground(muted());
        refreshParams();
    }

    // ---------------------------------------------------------------- 颜色标记

    /** 有色行的排序方式：默认只把有色的顶上来，另两个按色号排。 */
    private enum ColorSort {
        DEFAULT("默认（有色置顶）", "", Marks.SORT_DEFAULT),
        ASC("按颜色 红 → 紫", "颜色↑", Marks.SORT_ASC),
        DESC("按颜色 紫 → 红", "颜色↓", Marks.SORT_DESC);

        final String label;
        final String shortLabel;
        final int mode;

        ColorSort(String label, String shortLabel, int mode) {
            this.label = label;
            this.shortLabel = shortLabel;
            this.mode = mode;
        }

        @Override
        public String toString() {
            return label;
        }
    }

    /** 一条待上色的目标：种类 + 作用域 + 键，三种表格共用一套菜单。 */
    private static final class MarkTarget {
        final String kind;
        final String scope;
        final String target;

        MarkTarget(String kind, String scope, String target) {
            this.kind = kind;
            this.scope = scope == null ? "" : scope;
            this.target = target == null ? "" : target;
        }
    }

    private int pathColor(Endpoint ep) {
        return ep == null ? 0 : store.marks().color(Marks.PATH, ep.domainKey(), ep.key);
    }

    private int paramColor(Params.ParamStat st) {
        return st == null ? 0 : store.marks().color(Marks.PARAM, "", paramKey(st));
    }

    private static String paramKey(Params.ParamStat st) {
        return Marks.paramTarget(st.where, st.name);
    }

    /** 路径排序用：规则本身在 {@link Marks#compare}，别在这儿抄第二份。 */
    private static int compareColor(int a, int b, ColorSort mode) {
        return Marks.compare(a, b, mode == null ? Marks.SORT_DEFAULT : mode.mode);
    }

    /** 「标记颜色 ▸ 红/橙/…/清除」。选中多行就一起标，标完把选中还回去。 */
    private JMenu markMenu(String title, String hint, List<MarkTarget> targets, boolean forPath) {
        JMenu menu = new JMenu(title);
        menu.setToolTipText(hint);
        if (targets.isEmpty()) {
            menu.setEnabled(false);
            return menu;
        }
        int common = store.marks().color(targets.get(0).kind, targets.get(0).scope, targets.get(0).target);
        for (MarkTarget t : targets) {
            if (store.marks().color(t.kind, t.scope, t.target) != common) {
                common = -1; // 选中行颜色不一致：都不打「当前」标记
                break;
            }
        }
        for (int i = 1; i <= Marks.NAMES.length; i++) {
            final int color = i;
            JMenuItem mi = new JMenuItem(Marks.NAMES[i - 1] + (common == i ? "（当前）" : ""), Marks.swatch(i));
            mi.addActionListener(e -> applyMark(targets, color, forPath));
            menu.add(mi);
        }
        menu.addSeparator();
        JMenuItem clear = new JMenuItem(targets.size() > 1 ? "清除颜色（" + targets.size() + " 行）" : "清除颜色");
        clear.setEnabled(common != 0);
        clear.addActionListener(e -> applyMark(targets, 0, forPath));
        menu.add(clear);
        return menu;
    }

    private void applyMark(List<MarkTarget> targets, int color, boolean forPath) {
        int changed = 0;
        for (MarkTarget t : targets) {
            if (store.marks().set(t.kind, t.scope, t.target, color)) {
                changed++;
            }
        }
        if (changed == 0) {
            return; // 颜色没变，不用重排（重排会让行跳走，白晃一下）
        }
        if (forPath) {
            applyFilter();
        } else {
            refreshParams();
        }
        // 有色行会被顶到最上面：把选中还给刚才那几行，否则连点两次就标到别的行了
        Set<String> hit = new HashSet<>();
        for (MarkTarget t : targets) {
            hit.add(t.target);
        }
        javax.swing.ListSelectionModel sel = forPath ? pathTable.getSelectionModel() : paramTable.getSelectionModel();
        sel.setValueIsAdjusting(true);
        sel.clearSelection();
        if (forPath) {
            for (int i = 0; i < visible.size(); i++) {
                if (hit.contains(visible.get(i).ep.key)) {
                    sel.addSelectionInterval(i, i);
                }
            }
        } else {
            for (int i = 0; i < paramRows.size(); i++) {
                if (hit.contains(paramKey(paramRows.get(i)))) {
                    sel.addSelectionInterval(i, i);
                }
            }
        }
        sel.setValueIsAdjusting(false);
    }

    /** 供高级搜索取值的行；数字列给字符串形式，{@link SearchRule} 会自己转。 */
    private Map<String, String> pathRow(Endpoint ep) {
        Map<String, String> row = new LinkedHashMap<>();
        row.put("path", ep.path);
        row.put("method", ep.method);
        row.put("url", ep.url);
        row.put("status", String.valueOf(ep.status));
        row.put("bytes", String.valueOf(ep.responseLength));
        row.put("params", String.valueOf(ep.paramCount()));
        row.put("tool", ep.tool);
        row.put("color", Marks.name(pathColor(ep)));
        return row;
    }

    private Map<String, String> paramRow(Params.ParamStat st) {
        Map<String, String> row = new LinkedHashMap<>();
        row.put("name", st.name);
        row.put("full", st.fullPath);
        row.put("where", st.where);
        row.put("example", st.example);
        row.put("endpoints", String.valueOf(st.endpoints));
        row.put("color", Marks.name(paramColor(st)));
        return row;
    }

    private void refreshParams() {
        updateParamSourceButton();
        List<Params.ParamStat> stats = currentStats();
        List<Endpoint> scope = selectedEndpoints();
        String q = paramFilter.getText().trim();
        boolean ic = paramIgnoreCase.isSelected();
        boolean re = paramRegex.isSelected();
        boolean inv = paramInvert.isSelected();
        List<SearchRule> rules = paramRules;
        boolean anySource = paramSources.isEmpty();
        boolean active = !q.isEmpty() || !rules.isEmpty();

        paramModel.setRowCount(0);
        paramRows.clear();
        List<Params.ParamStat> picked = new ArrayList<>();
        for (Params.ParamStat st : stats) {
            if (!anySource && !paramSources.contains(st.where)) {
                continue;
            }
            // 文本框对四个字段一起匹配，一条条件能跨字段命中
            String hay = st.name + "\n" + st.fullPath + "\n" + st.where + "\n" + st.example;
            boolean hit = q.isEmpty() || TextFilter.contains(hay, q, ic, re);
            if (hit && !rules.isEmpty()) {
                hit = SearchRule.match(rules, paramRow(st), ic);
            }
            if (active && inv == hit) {
                continue;
            }
            picked.add(st);
        }
        // 和路径表同一套规则：有色置顶，或按颜色序号排（稳定排序，同档内不乱跳）
        if (!picked.isEmpty()) {
            picked.sort((a, b) -> compareColor(paramColor(a), paramColor(b), paramSort));
        }
        for (Params.ParamStat st : picked) {
            paramRows.add(st);
            paramModel.addRow(new Object[]{st.name, st.where, st.endpoints, st.example});
        }
        paramCount.setText("参数 " + paramRows.size() + " / " + stats.size()
                + (scope.size() == endpoints.size() ? "（全域名）" : "（选中接口）")
                + (anySource ? "" : " · 来源 " + sourceLabel())
                + (rules.isEmpty() ? "" : " · 高级 " + rules.size())
                + (paramSort == ColorSort.DEFAULT ? "" : " · " + paramSort.shortLabel));
        paramCount.setForeground(muted());
    }

    /** 当前该看哪批参数：选中了接口就看这几个，否则看整个域名（走缓存，别每次重算）。 */
    private List<Params.ParamStat> currentStats() {
        List<Endpoint> scope = selectedEndpoints();
        return scope == endpoints ? statsCache
                : Params.stats(scope, HeaderPolicy.collect(scope), store.settings().maxResponseFields());
    }

    /** 按 PARAM_SOURCES 的固定顺序拼来源名，集合是 HashSet，直接用会跳序。 */
    private String sourceLabel() {
        StringBuilder sb = new StringBuilder();
        for (String s : PARAM_SOURCES) {
            if (!paramSources.contains(s)) {
                continue;
            }
            if (sb.length() > 0) {
                sb.append('+');
            }
            sb.append(s);
        }
        return sb.toString();
    }

    /** 有选中行就只看选中的接口，否则看当前域名的全部接口。 */
    private List<Endpoint> selectedEndpoints() {
        int[] selected = pathTable.getSelectedRows();
        if (selected.length == 0) {
            return endpoints;
        }
        List<Endpoint> out = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        for (int viewRow : selected) {
            PathRow r = rowAt(viewRow);
            if (r != null && seen.add(r.ep.key)) {
                out.add(r.ep);
            }
        }
        return out.isEmpty() ? endpoints : out;
    }

    /** 只取真正被选中的（不兜底成"全部"）——删除这类破坏性操作用它，别把整屏都删了。 */
    private List<Endpoint> checkedEndpoints() {
        List<Endpoint> out = new ArrayList<>();
        for (int viewRow : pathTable.getSelectedRows()) {
            PathRow r = rowAt(viewRow);
            if (r != null) {
                out.add(r.ep);
            }
        }
        return out;
    }

    /** 视图行 → 数据行（排序后视图与模型顺序不同，必须转换）。 */
    private PathRow rowAt(int viewRow) {
        if (viewRow < 0 || viewRow >= pathTable.getRowCount()) {
            return null;
        }
        int modelRow = pathTable.convertRowIndexToModel(viewRow);
        return modelRow >= 0 && modelRow < visible.size() ? visible.get(modelRow) : null;
    }

    private void updateStats() {
        int eps = store.endpointCount();
        int samples = store.sampleCount();
        statsLabel.setText("域名 " + store.domains().size() + " · 接口 " + eps
                + (samples > eps ? " · 样本 " + samples : "")
                + " · 跳过 " + store.skipped() + (store.isRecording() ? " · 采集中" : " · 已暂停"));
    }

    // ---------------------------------------------------------------- 动作

    private void chooseDir() {
        JFileChooser chooser = new JFileChooser(store.dir());
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        chooser.setDialogTitle("选择模板保存目录");
        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            File f = chooser.getSelectedFile();
            store.setDir(f);
            dirField.setText(f.getAbsolutePath());
            store.flushAll();
        }
    }

    /** 设置页：收录范围（黑/白名单）+ 响应范围（解析上限、字段上限）。 */
    private void editSettings() {
        if (SettingsDialog.show(this, store)) {
            refreshAll();     // 字段上限变了，参数表要重算
            info("设置已保存：" + store.settings().summary());
        }
    }

    /**
     * 请求头配置：粘一段报文进来，之后所有「发送到 Repeater」都套这份头。
     * <p>
     * 因为 SQLite 里不存请求头（token 会过期），还原时的认证信息就全靠这里，
     * 所以输入要足够宽容——从 Repeater 里 Ctrl+A 整段复制也能识别。
     */
    private void editHeaders() {
        if (java.awt.GraphicsEnvironment.isHeadless()) {
            info("当前环境没有界面，跳过请求头配置");
            return;
        }
        JTextArea area = new JTextArea(headers.raw(), 12, 64);
        area.setLineWrap(true);
        area.setFont(new java.awt.Font(java.awt.Font.MONOSPACED, java.awt.Font.PLAIN, 12));

        JLabel hint = new JLabel(HeaderProfile.describe(area.getText()));
        hint.setForeground(muted());
        area.getDocument().addDocumentListener(new SimpleDoc(() -> hint.setText(HeaderProfile.describe(area.getText()))));

        JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        JButton paste = new JButton("从剪贴板粘贴");
        paste.addActionListener(e -> {
            String text = clipboardText();
            if (text.isEmpty()) {
                hint.setText("剪贴板里没有文本");
                return;
            }
            area.setText(text);
        });
        bar.add(paste);
        JButton clear = new JButton("清空");
        clear.addActionListener(e -> area.setText(""));
        bar.add(clear);
        bar.add(new JLabel("留空则用每条请求自己抓到的头"));

        JPanel body = new JPanel(new BorderLayout(0, 6));
        body.add(new JLabel("一行一个 Key: Value；也可以直接粘贴 Repeater 里的整段报文："), BorderLayout.NORTH);
        body.add(new JScrollPane(area), BorderLayout.CENTER);
        JPanel south = new JPanel(new BorderLayout(0, 4));
        south.add(bar, BorderLayout.NORTH);
        south.add(hint, BorderLayout.SOUTH);
        body.add(south, BorderLayout.SOUTH);

        int ok = javax.swing.JOptionPane.showConfirmDialog(this, body, "请求头配置",
                javax.swing.JOptionPane.OK_CANCEL_OPTION, javax.swing.JOptionPane.PLAIN_MESSAGE);
        if (ok != javax.swing.JOptionPane.OK_OPTION) {
            return;
        }
        headers.save(area.getText());
        updateHeaderButton();
        info(headers.isEmpty()
                ? "请求头配置已清空，还原时使用各自抓到的头"
                : "已保存 " + headers.headers().size() + " 条请求头，还原时会整组替换");
    }

    private void updateHeaderButton() {
        int n = headers.headers().size();
        headerButton.setText(n == 0 ? "请求头…" : "请求头(" + n + ")");
        headerButton.setToolTipText(n == 0
                ? "配置还原时统一套用的请求头（Authorization / Cookie 等），支持整段粘贴 Repeater 报文自动识别"
                : "已配置 " + n + " 条，所有还原到 Repeater 的请求都会带上；点这里修改");
    }

    private static String clipboardText() {
        try {
            Object o = Toolkit.getDefaultToolkit().getSystemClipboard()
                    .getData(java.awt.datatransfer.DataFlavor.stringFlavor);
            return o == null ? "" : String.valueOf(o);
        } catch (Exception e) {
            return "";
        }
    }

    private void openDir() {
        try {
            Desktop.getDesktop().open(store.dir());
        } catch (Exception e) {
            info("打不开目录：" + e.getMessage());
        }
    }

    /**
     * 主动补捞 Proxy 历史。跑在后台线程，按钮上顺便当进度条用。
     * <p>
     * 不受「开始采集」开关影响 —— 用户点它就是明确要求现在读一遍历史。
     */
    private void startImportHistory() {
        if (importing) {
            return;
        }
        importing = true;
        importButton.setEnabled(false);
        importButton.setText("导入中…");

        new javax.swing.SwingWorker<HistoryImport.Result, int[]>() {
            @Override
            protected HistoryImport.Result doInBackground() {
                return HistoryImport.run(api, store, (done, total) -> publish(new int[]{done, total}));
            }

            @Override
            protected void process(java.util.List<int[]> chunks) {
                int[] last = chunks.get(chunks.size() - 1);
                importButton.setText("导入 " + last[0] + "/" + last[1]);
            }

            @Override
            protected void done() {
                importing = false;
                importButton.setEnabled(true);
                importButton.setText("导入历史");
                HistoryImport.Result r;
                try {
                    r = get();
                } catch (Exception ex) {
                    Throwable cause = ex.getCause() == null ? ex : ex.getCause();
                    r = new HistoryImport.Result();
                    r.error = String.valueOf(cause);
                }
                refreshAll(); // 不等 600ms 防抖，立刻把新数据摆出来
                if (r.error != null) {
                    api.logging().logToError("[yuc] 导入历史失败：" + r.error);
                }
                info(r.summary() + "\n\n落盘目录：" + store.dir().getAbsolutePath());
            }
        }.execute();
    }

    // ---------------------------------------------------------------- 导入 JSON

    /**
     * 导入 v3-lite 模板。
     * <p>
     * 两个入口放在同一个对话框里，因为量少时粘贴最快、量大时必须选文件：
     * 几百 KB 的 json 塞进 JTextArea 会卡，直接读文件就没这问题。
     */
    private void importJsonDialog() {
        if (java.awt.GraphicsEnvironment.isHeadless()) {
            info("当前环境没有界面，跳过 JSON 导入");
            return;
        }
        JTextArea area = new JTextArea(12, 68);
        area.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        area.setLineWrap(false);

        JLabel result = new JLabel("支持整份模板，也支持只贴一个 item");
        result.setForeground(muted());

        JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        JButton fromFile = new JButton("从文件导入…");
        fromFile.setToolTipText("可选多个文件（数据多的时候用这个，不会经过文本框）");
        fromFile.addActionListener(e -> {
            List<File> files = chooseJsonFiles();
            if (files.isEmpty()) {
                return;
            }
            result.setText(doImport(TemplateImport.loadFiles(files, "导入"), "文件 " + files.size() + " 个"));
        });
        bar.add(fromFile);
        JButton paste = new JButton("从剪贴板粘贴");
        paste.addActionListener(e -> {
            String text = clipboardText();
            if (text.isEmpty()) {
                result.setText("剪贴板里没有文本");
                return;
            }
            area.setText(text);
        });
        bar.add(paste);
        JButton clear = new JButton("清空");
        clear.addActionListener(e -> area.setText(""));
        bar.add(clear);

        JPanel south = new JPanel(new BorderLayout(0, 4));
        south.add(bar, BorderLayout.NORTH);
        south.add(result, BorderLayout.SOUTH);

        JPanel body = new JPanel(new BorderLayout(0, 6));
        body.setBorder(BorderFactory.createEmptyBorder(6, 8, 6, 8));
        body.add(new JLabel("把模板 json 贴进来（或选文件）："), BorderLayout.NORTH);
        body.add(new JScrollPane(area), BorderLayout.CENTER);
        body.add(south, BorderLayout.SOUTH);

        JDialog dialog = new JDialog(SwingUtilities.getWindowAncestor(this), "导入 JSON",
                java.awt.Dialog.ModalityType.APPLICATION_MODAL);
        dialog.setLayout(new BorderLayout());
        dialog.add(body, BorderLayout.CENTER);

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 6));
        JButton doPaste = new JButton("导入粘贴内容");
        doPaste.addActionListener(e -> {
            String text = area.getText();
            if (text.trim().isEmpty()) {
                result.setText("文本框是空的：先粘贴，或点「从文件导入…」");
                return;
            }
            result.setText(doImport(TemplateImport.parse(text, "导入"), "粘贴内容"));
        });
        buttons.add(doPaste);
        JButton close = new JButton("关闭");
        close.addActionListener(e -> dialog.dispose());
        buttons.add(close);
        dialog.add(buttons, BorderLayout.SOUTH);

        dialog.setSize(820, 560);
        dialog.setLocationRelativeTo(this);
        dialog.setVisible(true);
    }

    private List<File> chooseJsonFiles() {
        JFileChooser chooser = new JFileChooser(store.dir());
        chooser.setDialogTitle("选择要导入的模板 json（可多选）");
        chooser.setMultiSelectionEnabled(true);
        chooser.setFileFilter(new javax.swing.filechooser.FileNameExtensionFilter("模板 json", "json"));
        if (chooser.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) {
            return List.of();
        }
        File[] files = chooser.getSelectedFiles();
        if (files == null || files.length == 0) {
            File one = chooser.getSelectedFile();
            return one == null ? List.of() : List.of(one);
        }
        return new ArrayList<>(List.of(files));
    }

    /** 真正落地：解析出来的接口并进存储，然后立刻写盘 + 刷界面。 */
    private String doImport(List<Endpoint> eps, String from) {
        if (eps.isEmpty()) {
            return from + "：没解析出接口（需要有 base.host 和 items 数组）";
        }
        int added = store.importEndpoints(eps);
        store.flushAll();
        refreshAll();
        int skipped = eps.size() - added;
        return from + "：解析 " + eps.size() + " 个，新增 " + added + " 个"
                + (skipped > 0 ? "，跳过 " + skipped + " 个（已存在或重复）" : "");
    }

    private void clearCurrent() {
        // 选中分组时只清这个分组，别一按就把整库清掉（以前是这么干的，太危险）
        String what = selectedDomain != null ? selectedDomain
                : selectedGroup != null ? selectedGroup + " 分组" : "全部域名";
        if (!confirm("清空 " + what + " 的记录并覆盖对应的 json 文件？\n（节点保留，只是变成 0 条）", "清空")) {
            return;
        }
        if (selectedDomain != null) {
            store.clearDomain(selectedDomain);
        } else if (selectedGroup != null) {
            for (EndpointStore.Domain d : store.domains()) {
                if (Urls.rootDomain(d.host).equals(selectedGroup)) {
                    store.clearDomain(d.key);
                }
            }
        } else {
            store.clearAll();
        }
        refreshAll();
    }

    /** 把这个样本拼回请求，直接开一个 Repeater 标签。 */
    private void sendToRepeater(Endpoint ep) {
        if (ep == null) {
            return;
        }
        try {
            // 多档时把长度写进标签名，否则同接口开几个标签分不清发的是哪一档
            String tab = ep.sampleCount() > 1
                    ? Replay.tabName(ep) + " · " + ep.responseLength + "B"
                    : Replay.tabName(ep);
            api.repeater().sendToRepeater(Replay.toRepeaterRequest(ep, headers.headers()), tab);
            api.logging().logToOutput("[yuc] 已发送到 Repeater：" + ep.method + " " + ep.path
                    + "（" + ep.responseLength + " 字节那档）");
        } catch (Throwable t) {
            api.logging().logToError("[yuc] 发送到 Repeater 失败：" + t);
            info("发送失败：" + t.getMessage());
        }
    }

    private void showDetail() {
        int row = pathTable.getSelectedRow();
        PathRow r = row >= 0 ? rowAt(row) : null;
        if (r == null) {
            return;
        }
        Endpoint hit = r.ep;
        StringBuilder sb = new StringBuilder();
        sb.append("--- 请求（与发到 Repeater 的内容一致）---\n");
        sb.append(new String(hit.rawRequestBytes(headers.headers()), StandardCharsets.UTF_8)).append('\n');
        sb.append("--- 响应 ---\n");
        sb.append("状态 ").append(hit.status).append(" · ").append(hit.responseLength).append(" 字节")
                .append(" · 来源 ").append(hit.tool).append('\n');
        if (hit.responseContentType != null) {
            sb.append("Content-Type: ").append(hit.responseContentType).append('\n');
        }
        sb.append('\n').append(cut(hit.responseBody, 8000));

        JTextArea area = new JTextArea(sb.toString());
        area.setEditable(false);
        area.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));

        JDialog dialog = new JDialog(SwingUtilities.getWindowAncestor(this), hit.displayName(),
                java.awt.Dialog.ModalityType.APPLICATION_MODAL);
        dialog.setLayout(new BorderLayout());
        dialog.add(new JScrollPane(area), BorderLayout.CENTER);

        JPanel south = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 6));
        JButton toRepeater = new JButton("发送到 Repeater");
        toRepeater.addActionListener(e -> {
            sendToRepeater(hit);
            dialog.dispose();
        });
        south.add(toRepeater);
        JButton close = new JButton("关闭");
        close.addActionListener(e -> dialog.dispose());
        south.add(close);
        dialog.add(south, BorderLayout.SOUTH);

        dialog.setSize(900, 660);
        dialog.setLocationRelativeTo(this);
        dialog.setVisible(true);
    }

    private JPopupMenu pathPopup() {
        JPopupMenu menu = new JPopupMenu();
        Endpoint ep = selectedEndpoint();
        int count = ep == null ? 0 : ep.sampleCount();

        JMenuItem plain = item(count > 1 ? "发送到 Repeater（最长 " + ep.responseLength + " 字节）"
                        : "发送到 Repeater",
                () -> sendToRepeater(selectedEndpoint()));
        plain.setToolTipText(count > 1 ? "默认发最长响应那档；想发别的长度用下面一项" : null);
        menu.add(plain);

        JMenu byLength = new JMenu("按长度发送到 Repeater" + (count > 1 ? "（" + count + " 档）" : ""));
        byLength.setToolTipText("同一接口按响应长度留了多档，每档的参数集可能不同");
        if (count > 1) {
            List<Endpoint> samples = new ArrayList<>(ep.samples());
            // 长的排前面：最常用的（正常响应）放第一个
            samples.sort((a, b) -> Long.compare(b.responseLength, a.responseLength));
            for (Endpoint s : samples) {
                boolean primary = s.responseLength == ep.responseLength;
                JMenuItem mi = item(s.responseLength + " 字节 · 状态 " + s.status
                                + (primary ? " · 最长" : ""),
                        () -> sendToRepeater(s));
                mi.setToolTipText(tooltipOf(s, primary));
                byLength.add(mi);
            }
        } else {
            JMenuItem only = new JMenuItem("只有一档（" + (ep == null ? 0 : ep.responseLength) + " 字节）");
            only.setEnabled(false);
            byLength.add(only);
        }
        menu.add(byLength);

        menu.addSeparator();
        List<Endpoint> markable = new ArrayList<>(checkedEndpoints());
        if (markable.isEmpty() && ep != null) {
            markable.add(ep); // 没选中（右键空白处）就标右键指到的那行
        }
        List<MarkTarget> targets = new ArrayList<>();
        for (Endpoint e : markable) {
            targets.add(new MarkTarget(Marks.PATH, e.domainKey(), e.key));
        }
        menu.add(markMenu("标记颜色" + (targets.size() > 1 ? "（" + targets.size() + " 行）" : ""),
                "给接口上色，颜色存在库里、重启还在；默认排序会把有色行置顶", targets, true));
        menu.addSeparator();
        menu.add(item("复制路径（当前展示）", () -> copy(joinColumn(pathTable, 0))));
        menu.add(item("复制完整路径", () -> copy(joinFullPaths())));
        menu.add(item("复制完整 URL", () -> copy(joinUrls())));
        menu.add(item("复制该接口的模板 JSON", () -> {
            Endpoint cur = selectedEndpoint();
            if (cur != null) {
                copy(MiniJson.pretty(TemplateBuilder.item(cur, new LinkedHashSet<>())));
            }
        }));
        menu.addSeparator();

        int picked = pathTable.getSelectedRows().length;
        JMenuItem delete = item(picked > 1 ? "删除选中路径（" + picked + " 条）" : "删除该路径", this::deletePaths);
        delete.setToolTipText("删除后会把 json 里对应的 item 和数据库记录一起删掉");
        menu.add(delete);
        menu.add(item("查看详情", this::showDetail));
        return menu;
    }

    /** 长度档的悬停说明：把"这一档是什么"讲清楚，别让人靠猜。 */
    private static String tooltipOf(Endpoint s, boolean primary) {
        String when = new java.text.SimpleDateFormat("MM-dd HH:mm:ss")
                .format(new java.util.Date(s.lastSeen));
        return s.responseLength + " 字节 · 状态 " + s.status + " · 参数 " + s.paramCount() + " 个"
                + " · " + s.tool + " · " + when
                + (primary ? "（主样本：界面参数表与导出的模板都用它）" : "");
    }

    /**
     * 路径表「响应字节」那列：多档时标一下，免得以为只有一个长度；
     * 从模板导入的样本没有响应，长度是 0，直接标「模板」而不是显示一个 0。
     */
    private static String byteLabel(Endpoint ep) {
        int n = ep.sampleCount();
        if (ep.responseLength <= 0) {
            return n > 1 ? "模板 等" + n + "档" : "模板";
        }
        return n > 1 ? ep.responseLength + " 等" + n + "档" : String.valueOf(ep.responseLength);
    }

    /** 删除当前选中的路径（连带 json 里的 item 与库记录）。 */
    private void deletePaths() {
        List<Endpoint> picked = checkedEndpoints();
        if (picked.isEmpty()) {
            info("先在路径表里选中要删除的行");
            return;
        }
        StringBuilder sb = new StringBuilder("删除这 " + picked.size() + " 条接口？\n\n");
        for (int i = 0; i < picked.size() && i < 8; i++) {
            sb.append("  ").append(picked.get(i).method).append(' ').append(picked.get(i).path).append('\n');
        }
        if (picked.size() > 8) {
            sb.append("  …还有 ").append(picked.size() - 8).append(" 条\n");
        }
        sb.append("\n会同时从 json 和数据库里删掉，不可恢复。");
        if (!confirm(sb.toString(), "删除路径")) {
            return;
        }
        int n = store.removeEndpoints(picked);
        refreshAll();
        info("已删除 " + n + " 条接口，json 与数据库已同步");
    }

    private JPopupMenu paramPopup() {
        JPopupMenu menu = new JPopupMenu();
        menu.add(item("只看用到该参数的接口", () -> scopeToParam(selectedParamStat())));
        menu.addSeparator();

        List<MarkTarget> targets = new ArrayList<>();
        for (int viewRow : paramTable.getSelectedRows()) {
            int modelRow = paramTable.convertRowIndexToModel(viewRow);
            if (modelRow >= 0 && modelRow < paramRows.size()) {
                Params.ParamStat st = paramRows.get(modelRow);
                targets.add(new MarkTarget(Marks.PARAM, "", paramKey(st)));
            }
        }
        if (targets.isEmpty() && selectedParamStat() != null) {
            targets.add(new MarkTarget(Marks.PARAM, "", paramKey(selectedParamStat())));
        }
        menu.add(markMenu("标记颜色" + (targets.size() > 1 ? "（" + targets.size() + " 行）" : ""),
                "参数颜色按「位置 + 名字」记，跨域名共用；默认排序会把有色行置顶", targets, false));
        menu.addSeparator();

        menu.add(item("复制参数名", () -> copy(joinColumn(paramTable, 0))));
        menu.add(item("复制参数值", () -> copy(paramValues())));
        menu.add(item("复制完整路径", () -> copy(joinParamPaths())));

        int picked = paramTable.getSelectedRows().length;
        String title = picked > 0 ? "复制为 payload（选中 " + picked + " 个）" : "复制为 payload（全部可见）";
        JMenu copyAs = new JMenu(title);
        copyAs.add(item("raw    a=1&b=2", () -> copy(Payload.raw(selectedParamPairs()))));
        copyAs.add(item("json   {\"a\":\"1\"}", () -> copy(Payload.json(selectedParamPairs()))));
        copyAs.add(item("xml    <a>1</a>", () -> copy(Payload.xml(selectedParamPairs()))));
        copyAs.setEnabled(paramTable.getRowCount() > 0);
        menu.add(copyAs);
        return menu;
    }

    /**
     * 采集来源改多选（和参数来源同一套交互）。
     * <p>
     * 勾选项后面带「当前各来源有多少条」，用户不用盲勾。
     */
    private void editToolSources() {
        if (java.awt.GraphicsEnvironment.isHeadless()) {
            info("当前环境没有界面，跳过来源筛选");
            return;
        }
        Map<String, Integer> counts = new LinkedHashMap<>();
        for (String s : EndpointStore.SOURCE_NAMES) {
            counts.put(s, 0);
        }
        for (EndpointStore.Domain d : store.domains()) {
            for (Endpoint ep : store.endpoints(d.key)) {
                counts.merge(ep.tool, 1, Integer::sum);
            }
        }

        Map<String, JCheckBox> boxes = new LinkedHashMap<>();
        JPanel grid = new JPanel(new GridLayout(0, 2, 10, 4));
        for (String s : EndpointStore.SOURCE_NAMES) {
            int n = counts.getOrDefault(s, 0);
            // 这里不能像参数来源那样"0 条就置灰"：刚装插件时一条数据都没有，
            // 全灰掉等于开局就不能选，而这恰恰是最需要先选好来源的时候
            JCheckBox cb = new JCheckBox(s + "  (" + n + ")", toolSources.contains(s));
            boxes.put(s, cb);
            grid.add(cb);
        }

        JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        JButton all = new JButton("全选");
        all.addActionListener(e -> boxes.values().forEach(cb -> cb.setSelected(true)));
        bar.add(all);
        JButton none = new JButton("全不选");
        none.addActionListener(e -> boxes.values().forEach(cb -> cb.setSelected(false)));
        bar.add(none);
        JLabel hint = new JLabel("都不勾 = 采集全部来源");
        hint.setForeground(muted());
        bar.add(hint);

        JPanel body = new JPanel(new BorderLayout(0, 8));
        body.add(new JLabel("勾选要从哪些模块采集（可多选）："), BorderLayout.NORTH);
        body.add(grid, BorderLayout.CENTER);
        body.add(bar, BorderLayout.SOUTH);

        int ok = javax.swing.JOptionPane.showConfirmDialog(this, body, "采集来源",
                javax.swing.JOptionPane.OK_CANCEL_OPTION, javax.swing.JOptionPane.PLAIN_MESSAGE);
        if (ok != javax.swing.JOptionPane.OK_OPTION) {
            return;
        }
        toolSources.clear();
        for (Map.Entry<String, JCheckBox> e : boxes.entrySet()) {
            if (e.getValue().isSelected()) {
                toolSources.add(e.getKey());
            }
        }
        store.setToolFilter(toolSources);
        updateToolSourceButton();
        updateStats();
    }

    private void updateToolSourceButton() {
        if (toolSources.isEmpty()) {
            toolSourceButton.setText("来源：全部");
            toolSourceButton.setToolTipText("勾选要采集哪些模块发出的请求（可多选，都不勾 = 全部）");
            return;
        }
        // 不缩写、不写成「3 项」：来源名本身就是信息，压成数字反而要用户去弹窗里对
        String label = String.join("+", toolSources);
        toolSourceButton.setText("来源：" + label);
        toolSourceButton.setToolTipText("只采集：" + label + "；点这里改");
    }

    /**
     * 记录类型改多选（JSON / HTML）。
     * <p>
     * 和「来源」不同，这里**不许全不勾**：那样会变成一条都不记。全取消就退回只 JSON，
     * 弹框里的提示也写明了这一点。
     */
    private void editRecordTypes() {
        if (java.awt.GraphicsEnvironment.isHeadless()) {
            info("当前环境没有界面，跳过记录类型");
            return;
        }
        Map<String, Integer> counts = new LinkedHashMap<>();
        for (String t : Capture.TYPE_NAMES) {
            counts.put(t, 0);
        }
        for (EndpointStore.Domain d : store.domains()) {
            for (Endpoint ep : store.endpoints(d.key)) {
                String kind = Capture.kindOf(ep.responseContentType);
                if (kind != null) {
                    counts.merge(kind, 1, Integer::sum);
                }
            }
        }

        Map<String, JCheckBox> boxes = new LinkedHashMap<>();
        JPanel grid = new JPanel(new GridLayout(0, 2, 10, 4));
        java.util.Set<String> now = store.recordTypes();
        for (String t : Capture.TYPE_NAMES) {
            JCheckBox cb = new JCheckBox(t + "  (" + counts.getOrDefault(t, 0) + ")", now.contains(t));
            if (Capture.TYPE_HTML.equals(t)) {
                cb.setToolTipText("HTML 页面一个站能有几百个，开了会明显撑大接口表；默认不开");
            }
            boxes.put(t, cb);
            grid.add(cb);
        }

        JPanel body = new JPanel(new BorderLayout(0, 8));
        body.add(new JLabel("勾选要记录哪些响应类型（按响应 Content-Type 判定）："), BorderLayout.NORTH);
        body.add(grid, BorderLayout.CENTER);
        JLabel hint = new JLabel("至少留一个；一个都不勾会退回「只 JSON」。HTML 默认不记。");
        hint.setForeground(muted());
        body.add(hint, BorderLayout.SOUTH);

        int ok = javax.swing.JOptionPane.showConfirmDialog(this, body, "记录类型",
                javax.swing.JOptionPane.OK_CANCEL_OPTION, javax.swing.JOptionPane.PLAIN_MESSAGE);
        if (ok != javax.swing.JOptionPane.OK_OPTION) {
            return;
        }
        List<String> picked = new ArrayList<>();
        for (Map.Entry<String, JCheckBox> e : boxes.entrySet()) {
            if (e.getValue().isSelected()) {
                picked.add(e.getKey());
            }
        }
        store.setRecordTypes(picked); // 空集合它自己会退回 JSON
        updateTypeButton();
        updateStats();
    }

    private void updateTypeButton() {
        java.util.Set<String> types = store.recordTypes();
        StringBuilder label = new StringBuilder();
        for (String t : Capture.TYPE_NAMES) {
            if (types.contains(t)) {
                if (label.length() > 0) {
                    label.append('+');
                }
                label.append(t);
            }
        }
        typeButton.setText("类型：" + label);
        typeButton.setToolTipText(types.contains(Capture.TYPE_HTML)
                ? "正在记录：" + label + "（HTML 会明显撑大接口表）；点这里改"
                : "正在记录：" + label + "；点这里可以打开 HTML");
    }

    /**
     * 参数来源改多选：一个接口同时带 query / Cookie / 表单是常态，
     * 单选下拉只能一次看一类，来回切太碎。
     * <p>
     * 勾选项后面带上「当前这一屏各来源有多少个」，用户不用盲勾。
     */
    private void editParamSources() {
        if (java.awt.GraphicsEnvironment.isHeadless()) {
            info("当前环境没有界面，跳过来源筛选");
            return;
        }
        Map<String, Integer> counts = new LinkedHashMap<>();
        for (String s : PARAM_SOURCES) {
            counts.put(s, 0);
        }
        for (Params.ParamStat st : currentStats()) {
            counts.merge(st.where, 1, Integer::sum);
        }

        Map<String, JCheckBox> boxes = new LinkedHashMap<>();
        JPanel grid = new JPanel(new GridLayout(0, 2, 10, 4));
        for (String s : PARAM_SOURCES) {
            JCheckBox cb = new JCheckBox(s + "  (" + counts.getOrDefault(s, 0) + ")", paramSources.contains(s));
            cb.setEnabled(counts.getOrDefault(s, 0) > 0 || paramSources.contains(s));
            boxes.put(s, cb);
            grid.add(cb);
        }

        JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        JButton all = new JButton("全选");
        all.addActionListener(e -> boxes.values().forEach(cb -> {
            if (cb.isEnabled()) {
                cb.setSelected(true);
            }
        }));
        bar.add(all);
        JButton none = new JButton("全不选");
        none.addActionListener(e -> boxes.values().forEach(cb -> cb.setSelected(false)));
        bar.add(none);
        JLabel hint = new JLabel("都不勾 = 显示全部来源");
        hint.setForeground(muted());
        bar.add(hint);

        JPanel body = new JPanel(new BorderLayout(0, 8));
        body.add(new JLabel("勾选要显示的参数来源（可多选）："), BorderLayout.NORTH);
        body.add(grid, BorderLayout.CENTER);
        body.add(bar, BorderLayout.SOUTH);

        int ok = javax.swing.JOptionPane.showConfirmDialog(this, body, "参数来源",
                javax.swing.JOptionPane.OK_CANCEL_OPTION, javax.swing.JOptionPane.PLAIN_MESSAGE);
        if (ok != javax.swing.JOptionPane.OK_OPTION) {
            return;
        }
        paramSources.clear();
        for (Map.Entry<String, JCheckBox> e : boxes.entrySet()) {
            if (e.getValue().isSelected()) {
                paramSources.add(e.getKey());
            }
        }
        updateParamSourceButton();
        refreshParams();
    }

    private void updateParamSourceButton() {
        if (paramSources.isEmpty()) {
            paramSourceButton.setText("来源：全部");
            paramSourceButton.setToolTipText("按参数来源多选筛选（可同时勾选查询 + 请求体等）");
            return;
        }
        String label = sourceLabel();
        paramSourceButton.setText(label.length() > 18 ? "来源：" + paramSources.size() + " 项" : "来源：" + label);
        paramSourceButton.setToolTipText("只显示：" + label + "；点这里改");
    }

    /**
     * 高级搜索：按列 + 关系 + 值拼条件，不再让用户手写表达式。
     * <p>
     * 关系的可选项跟着列走：文本列给「包含 / 不包含 / 等于 / 不等于 / 开头是 / 结尾是 / 正则」，
     * 数字列（状态码、响应字节、参数个数、接口数）再多给「大于 / 大于等于 / 小于 / 小于等于」。
     * 行首的「且 / 或」决定它和前一条怎么连，第一条忽略。
     */
    private void editAdvanced(boolean forPath) {
        if (java.awt.GraphicsEnvironment.isHeadless()) {
            info("当前环境没有界面，跳过高级搜索");
            return;
        }
        SearchRule.Field[] fields = forPath ? SearchRule.PATH_FIELDS : SearchRule.PARAM_FIELDS;
        List<SearchRule> current = forPath ? pathRules : paramRules;

        JPanel rows = new JPanel();
        rows.setLayout(new BoxLayout(rows, BoxLayout.Y_AXIS));
        List<RuleEditor> editors = new ArrayList<>();
        for (SearchRule r : current) {
            addRuleRow(rows, editors, fields, r);
        }
        if (editors.isEmpty()) {
            addRuleRow(rows, editors, fields, null);
        }

        JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        JButton add = new JButton("+ 添加条件");
        add.addActionListener(e -> {
            addRuleRow(rows, editors, fields, null);
            rows.revalidate();
            rows.repaint();
        });
        bar.add(add);
        JLabel hint = new JLabel("「且」优先于「或」；没填值的条件会被忽略");
        hint.setForeground(muted());
        bar.add(hint);

        // 排序只在这里能改：颜色不是表格的一列，点表头排不了它
        JComboBox<ColorSort> sortBox = new JComboBox<>(ColorSort.values());
        sortBox.setSelectedItem(forPath ? pathSort : paramSort);
        sortBox.setToolTipText("颜色不占一列，所以只能在这儿按颜色排；「重置」会回到默认（有色置顶）");

        JPanel body = new JPanel(new BorderLayout(0, 8));
        JPanel head = new JPanel(new BorderLayout());
        head.add(new JLabel("选择列 → 选择关系 → 填值（第一行前面的「且/或」不起作用）："), BorderLayout.WEST);
        JPanel sortBar = new JPanel(new FlowLayout(FlowLayout.RIGHT, 4, 0));
        sortBar.add(new JLabel("排序"));
        sortBar.add(sortBox);
        head.add(sortBar, BorderLayout.EAST);
        body.add(head, BorderLayout.NORTH);
        body.add(new JScrollPane(rows), BorderLayout.CENTER);
        body.add(bar, BorderLayout.SOUTH);
        body.setPreferredSize(new Dimension(820, 300));

        int ok = javax.swing.JOptionPane.showConfirmDialog(this, body,
                forPath ? "路径高级搜索" : "参数高级搜索",
                javax.swing.JOptionPane.OK_CANCEL_OPTION, javax.swing.JOptionPane.PLAIN_MESSAGE);
        if (ok != javax.swing.JOptionPane.OK_OPTION) {
            return;
        }

        List<SearchRule> next = new ArrayList<>();
        for (RuleEditor ed : editors) {
            SearchRule.Field f = (SearchRule.Field) ed.field.getSelectedItem();
            SearchRule.Op op = (SearchRule.Op) ed.op.getSelectedItem();
            String value = ed.valueText();
            if (f == null || op == null || value.isEmpty()) {
                continue; // 空行当没写
            }
            next.add(new SearchRule(f.key, op, value, ed.combo.getSelectedIndex() == 1));
        }
        ColorSort sort = (ColorSort) sortBox.getSelectedItem();
        if (forPath) {
            pathRules = next;
            pathSort = sort == null ? ColorSort.DEFAULT : sort;
            applyFilter();
        } else {
            paramRules = next;
            paramSort = sort == null ? ColorSort.DEFAULT : sort;
            refreshParams();
        }
        updateAdvancedButtons();
    }

    /** 往弹框里加一行条件编辑控件。 */
    private static void addRuleRow(JPanel rows, List<RuleEditor> editors,
                                   SearchRule.Field[] fields, SearchRule seed) {
        RuleEditor ed = new RuleEditor(fields);
        if (seed != null) {
            ed.select(seed);
        }
        ed.remove.addActionListener(e -> {
            if (editors.size() <= 1) {
                return; // 至少留一行，别让整个框空掉
            }
            editors.remove(ed);
            rows.remove(ed.row);
            rows.revalidate();
            rows.repaint();
        });
        editors.add(ed);
        rows.add(ed.row);
    }

    private void updateAdvancedButtons() {
        styleAdvanced(pathAdvancedButton, pathRules, pathSort, "路径");
        styleAdvanced(paramAdvancedButton, paramRules, paramSort, "参数");
    }

    private static void styleAdvanced(JButton button, List<SearchRule> rules, ColorSort sort, String what) {
        StringBuilder text = new StringBuilder("高级");
        if (!rules.isEmpty()) {
            text.append('(').append(rules.size()).append(')');
        }
        if (sort != ColorSort.DEFAULT) {
            text.append(" · ").append(sort.shortLabel);
        }
        button.setText(text.toString());

        StringBuilder tip = new StringBuilder();
        if (rules.isEmpty()) {
            tip.append(what).append("高级搜索：按「列 + 关系 + 值」筛选，可拼「且 / 或」");
        } else {
            tip.append("当前条件：").append(SearchRule.describe(rules)).append("（点这里改）");
        }
        if (sort != ColorSort.DEFAULT) {
            tip.append("；排序：").append(sort.label);
        }
        button.setToolTipText(tip.toString());
    }

    /** 参数 → 反查来源接口：把路径表收敛到"用到这个参数的那几个接口"。 */
    private void scopeToParam(Params.ParamStat st) {
        if (st == null) {
            return;
        }
        paramScopeKeys = new HashSet<>(st.endpointKeys);
        paramScopeName = st.name + "（" + st.where + "）";
        applyFilter();
    }

    private void resetPathFilters() {
        pathFilter.setText("");
        pathInvert.setSelected(false);
        pathRules = new ArrayList<>();
        pathSort = ColorSort.DEFAULT; // 重置回到默认排序：有色置顶
        updateAdvancedButtons();
        paramScopeKeys = null;
        paramScopeName = null;
        applyFilter();
    }

    private void resetParamFilters() {
        paramFilter.setText("");
        paramInvert.setSelected(false);
        paramRules = new ArrayList<>();
        paramSort = ColorSort.DEFAULT;
        paramSources.clear();
        updateAdvancedButtons();
        updateParamSourceButton();
        refreshParams();
    }

    private Params.ParamStat selectedParamStat() {
        int row = paramTable.getSelectedRow();
        if (row < 0) {
            return null;
        }
        int modelRow = paramTable.convertRowIndexToModel(row);
        return modelRow >= 0 && modelRow < paramRows.size() ? paramRows.get(modelRow) : null;
    }

    private Endpoint selectedEndpoint() {
        int row = pathTable.getSelectedRow();
        if (row < 0 && pathTable.getRowCount() > 0) {
            row = 0;
        }
        PathRow r = row >= 0 ? rowAt(row) : null;
        return r != null ? r.ep : (endpoints.isEmpty() ? null : endpoints.get(0));
    }

    // ---------------------------------------------------------------- 树的右键

    private void treePopup(MouseEvent e) {
        if (!e.isPopupTrigger()) {
            return;
        }
        TreePath path = domainTree.getPathForLocation(e.getX(), e.getY());
        if (path == null) {
            return;
        }
        domainTree.setSelectionPath(path);
        Object o = ((DefaultMutableTreeNode) path.getLastPathComponent()).getUserObject();

        JPopupMenu menu = new JPopupMenu();
        if (o instanceof DomainNode) {
            String key = ((DomainNode) o).key;
            EndpointStore.Domain d = store.domain(key);
            JMenuItem del = item("删除该域名（" + (d == null ? 0 : d.size()) + " 个接口）", () -> deleteDomain(key));
            del.setToolTipText("内存、数据库、json 文件一起删掉");
            menu.add(del);
        } else if (o instanceof GroupNode) {
            String name = ((GroupNode) o).name;
            JMenuItem del = item("删除该分组（" + name + "）", () -> deleteGroup(name));
            del.setToolTipText("把这个分组下所有域名连同 json 一起删掉");
            menu.add(del);
        } else {
            JMenuItem all = item("清空全部域名", this::clearCurrent);
            menu.add(all);
        }
        menu.show(domainTree, e.getX(), e.getY());
    }

    private void deleteDomain(String key) {
        EndpointStore.Domain d = store.domain(key);
        if (d == null) {
            return;
        }
        String file = TemplateBuilder.fileName(d.host, d.port);
        if (!confirm("删除 " + d.label() + "（" + d.size() + " 个接口）？\n\n"
                + "会同时删掉数据库记录和 " + file + "，不可恢复。", "删除域名")) {
            return;
        }
        store.removeDomain(key);
        if (key.equals(selectedDomain)) {
            selectedDomain = null;
        }
        refreshAll();
    }

    private void deleteGroup(String name) {
        List<EndpointStore.Domain> hits = new ArrayList<>();
        int eps = 0;
        for (EndpointStore.Domain d : store.domains()) {
            if (Urls.rootDomain(d.host).equals(name)) {
                hits.add(d);
                eps += d.size();
            }
        }
        if (hits.isEmpty()) {
            return;
        }
        if (!confirm("删除 " + name + " 下的 " + hits.size() + " 个域名（" + eps + " 个接口）？\n\n"
                + "每份 json 文件和数据库记录都会一起删掉，不可恢复。", "删除分组")) {
            return;
        }
        for (EndpointStore.Domain d : hits) {
            store.removeDomain(d.key);
        }
        if (name.equals(selectedGroup)) {
            selectedGroup = null;
            selectedDomain = null;
        }
        expandedGroups.remove(name);
        refreshAll();
    }

    // ---------------------------------------------------------------- 小工具

    private void maybePopup(MouseEvent e, JTable table, java.util.function.Supplier<JPopupMenu> supplier) {
        if (e.isPopupTrigger()) {
            int row = table.rowAtPoint(e.getPoint());
            if (row >= 0 && !table.isRowSelected(row)) {
                table.setRowSelectionInterval(row, row);
            }
            supplier.get().show(table, e.getX(), e.getY());
        }
    }

    private JMenuItem item(String text, Runnable action) {
        JMenuItem mi = new JMenuItem(text);
        mi.addActionListener(e -> action.run());
        return mi;
    }

    private String joinColumn(JTable table, int column) {
        StringBuilder sb = new StringBuilder();
        for (int viewRow : visibleRows(table)) {
            if (sb.length() > 0) {
                sb.append('\n');
            }
            sb.append(table.getValueAt(viewRow, column));
        }
        return sb.toString();
    }

    /** 参数表选中行 → 完整参数路径（没选中就是全部可见行）。 */
    private String joinParamPaths() {
        StringBuilder sb = new StringBuilder();
        for (int viewRow : visibleRows(paramTable)) {
            int modelRow = paramTable.convertRowIndexToModel(viewRow);
            if (modelRow < 0 || modelRow >= paramRows.size()) {
                continue;
            }
            if (sb.length() > 0) {
                sb.append('\n');
            }
            sb.append(paramRows.get(modelRow).fullPath);
        }
        return sb.toString();
    }

    /**
     * 参数表选中行 → 值，一行一个（没选中就是全部可见行）。
     * <p>
     * 用的是 {@code payload}（完整值）而不是表格里那个 {@code example}——表格超长会加 `…`，
     * 复制出去要是残的就白复制了。多选时按行拼，不额外加 {@code name=}，保持"就是值本身"。
     */
    private String paramValues() {
        StringBuilder sb = new StringBuilder();
        for (int viewRow : visibleRows(paramTable)) {
            int modelRow = paramTable.convertRowIndexToModel(viewRow);
            if (modelRow < 0 || modelRow >= paramRows.size()) {
                continue;
            }
            if (sb.length() > 0) {
                sb.append('\n');
            }
            sb.append(paramRows.get(modelRow).payload);
        }
        return sb.toString();
    }

    /** 参数表选中行 → {名字, 完整值}，给「复制为 payload」用。 */
    private List<String[]> selectedParamPairs() {
        List<String[]> out = new ArrayList<>();
        for (int viewRow : visibleRows(paramTable)) {
            int modelRow = paramTable.convertRowIndexToModel(viewRow);
            if (modelRow < 0 || modelRow >= paramRows.size()) {
                continue;
            }
            Params.ParamStat st = paramRows.get(modelRow);
            out.add(new String[]{st.name, st.payload});
        }
        return out;
    }

    private String joinFullPaths() {
        StringBuilder sb = new StringBuilder();
        for (int viewRow : visibleRows(pathTable)) {
            PathRow r = rowAt(viewRow);
            if (r == null) {
                continue;
            }
            if (sb.length() > 0) {
                sb.append('\n');
            }
            sb.append(r.ep.path);
        }
        return sb.toString();
    }

    private String joinUrls() {
        StringBuilder sb = new StringBuilder();
        for (int viewRow : visibleRows(pathTable)) {
            PathRow r = rowAt(viewRow);
            if (r == null) {
                continue;
            }
            if (sb.length() > 0) {
                sb.append('\n');
            }
            sb.append(r.ep.url);
        }
        return sb.toString();
    }

    /** 有选中就只处理选中的，没选中就是当前可见的全部。 */
    private int[] visibleRows(JTable table) {
        int[] selected = table.getSelectedRows();
        if (selected.length > 0) {
            return selected;
        }
        int[] all = new int[table.getRowCount()];
        for (int i = 0; i < all.length; i++) {
            all[i] = i;
        }
        return all;
    }

    private void copy(String text) {
        if (text == null || text.isEmpty()) {
            info("没有可复制的内容");
            return;
        }
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(text), null);
    }

    private void info(String message) {
        if (java.awt.GraphicsEnvironment.isHeadless()) {
            // 离线自测里没有显示器，直接打到 stdout
            System.out.println("[ui] " + message.replace('\n', ' '));
            return;
        }
        javax.swing.JOptionPane.showMessageDialog(this, message, "yuc", javax.swing.JOptionPane.INFORMATION_MESSAGE);
    }

    /** 危险操作确认。离线自测没有对话框可用，一律当"用户拒绝了"，绝不在无界面时静默删除。 */
    private boolean confirm(String message, String title) {
        if (java.awt.GraphicsEnvironment.isHeadless()) {
            System.out.println("[ui] 无界面，跳过确认：" + message.replace('\n', ' '));
            return false;
        }
        return javax.swing.JOptionPane.showConfirmDialog(this, message, title,
                javax.swing.JOptionPane.OK_CANCEL_OPTION,
                javax.swing.JOptionPane.WARNING_MESSAGE) == javax.swing.JOptionPane.OK_OPTION;
    }

    private static String cut(String s, int max) {
        if (s == null) {
            return "";
        }
        return s.length() > max ? s.substring(0, max) + "\n…（已截断，共 " + s.length() + " 字符）" : s;
    }

    private static java.awt.Color muted() {
        return javax.swing.UIManager.getColor("Label.disabledForeground");
    }

    /**
     * 给整张表套一层「按行上底色」的渲染器。
     * <p>
     * 包在原有渲染器外面、而不是替换它：数字列靠右、字符串列靠左这些对齐行为要原样保留；
     * 选中行不染色，用系统选中色（否则选中的那行看不出被选中）。
     * 底色由 {@link Marks#tint} 按当前表格底色算，浅色 / 深色主题都不会把文字压得看不见。
     */
    private static void paintRows(JTable table, java.util.function.IntFunction<Integer> colorOfModelRow) {
        java.awt.Color bg = table.getBackground();
        javax.swing.table.TableCellRenderer base = table.getDefaultRenderer(Object.class);
        for (int i = 0; i < table.getColumnModel().getColumnCount(); i++) {
            table.getColumnModel().getColumn(i).setCellRenderer(new javax.swing.table.TableCellRenderer() {
                @Override
                public java.awt.Component getTableCellRendererComponent(JTable t, Object value, boolean selected,
                                                                       boolean focused, int row, int column) {
                    java.awt.Component c = base.getTableCellRendererComponent(t, value, selected, focused, row, column);
                    // 选中行一律用系统选中色，别覆盖（渲染器是复用的，进了不染色的分支必须显式设回底色）
                    if (c instanceof javax.swing.JComponent && !selected) {
                        int color = colorOfModelRow.apply(t.convertRowIndexToModel(row));
                        c.setBackground(color > 0 ? Marks.tint(color, bg) : bg);
                        ((javax.swing.JComponent) c).setOpaque(true);
                    }
                    return c;
                }
            });
        }
    }

    private static DefaultTableModel tableModel(Object[] columns) {
        return new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
    }

    // ---------------------------------------------------------------- 内部类型

    /** 树节点上的数据：key 为空表示「全部」。 */
    private static final class DomainNode {
        final String key;
        final String label;

        DomainNode(String key, String label) {
            this.key = key;
            this.label = label;
        }

        @Override
        public String toString() {
            return label;
        }
    }

    /** 根域分组节点（demo.com.cn / 10.0.0.0/24），点它就看这一组下所有机器的接口。 */
    private static final class GroupNode {
        final String name;
        final String label;
        final int count;

        GroupNode(String name, String label, int count) {
            this.name = name;
            this.label = label;
            this.count = count;
        }

        @Override
        public String toString() {
            return label;
        }
    }

    private static final class PathRow {
        final Endpoint ep;
        final int paramCount;

        PathRow(Endpoint ep, int paramCount) {
            this.ep = ep;
            this.paramCount = paramCount;
        }
    }

    /**
     * 高级搜索弹框里的一行：[且/或] [列] [关系] [值] [×]。
     * <p>
     * 列一变就重建关系的可选项——数字列才能用「大于/小于」，混在一起会让人以为比大小对文本也有效。
     * 值的控件也跟着列走：像「颜色」这种只有几项可选的列给下拉，别让人手打「红」还是「红色」。
     */
    private static final class RuleEditor {
        final JComboBox<String> combo = new JComboBox<>(new String[]{"且", "或"});
        final JComboBox<SearchRule.Field> field;
        final JComboBox<SearchRule.Op> op = new JComboBox<>();
        final JTextField value = new JTextField(16);
        final JComboBox<String> pick = new JComboBox<>();
        /** 值的容器：里面永远只放一个控件（文本框或下拉），换列时整个换掉。 */
        final JPanel valueBox = new JPanel(new BorderLayout());
        final JButton remove = new JButton("×");
        final JPanel row = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        private boolean usingPick;

        RuleEditor(SearchRule.Field[] fields) {
            field = new JComboBox<>(fields);
            value.setToolTipText("填要比对的值；空着表示这条不生效");
            pick.setToolTipText("从这几项里挑一个");
            remove.setToolTipText("删掉这一条");
            remove.setMargin(new java.awt.Insets(0, 4, 0, 4));
            combo.setToolTipText("和上一条的关系：「且」要求同时成立，「或」满足一个即可");
            field.setToolTipText("要比对的列");
            op.setToolTipText("怎么比");
            fillOps();
            fillValue();
            field.addActionListener(e -> {
                fillOps();
                fillValue();
            });
            row.add(combo);
            row.add(field);
            row.add(op);
            row.add(valueBox);
            row.add(remove);
        }

        private void fillOps() {
            Object keep = op.getSelectedItem();
            op.removeAllItems();
            SearchRule.Field f = (SearchRule.Field) field.getSelectedItem();
            for (SearchRule.Op o : SearchRule.Op.values()) {
                if (o.numeric() && (f == null || !f.numeric)) {
                    continue;
                }
                op.addItem(o);
            }
            // 换列时尽量保住已选的关系；不适用（比如「大于」换到文本列）就退回第一项，
            // 直接 setSelectedItem 塞一个列表里没有的值会让下拉显示一个选不中的项
            if (keep != null) {
                for (int i = 0; i < op.getItemCount(); i++) {
                    if (op.getItemAt(i) == keep) {
                        op.setSelectedIndex(i);
                        return;
                    }
                }
            }
            if (op.getItemCount() > 0) {
                op.setSelectedIndex(0);
            }
        }

        /** 有候选值的列换成下拉，其余仍是自由填写的文本框。 */
        private void fillValue() {
            SearchRule.Field f = (SearchRule.Field) field.getSelectedItem();
            valueBox.removeAll();
            if (f != null && f.options != null) {
                String keep = usingPick ? (String) pick.getSelectedItem() : value.getText().trim();
                pick.removeAllItems();
                for (String o : f.options) {
                    pick.addItem(o);
                }
                if (keep != null && !keep.isEmpty()) {
                    pick.setSelectedItem(keep);
                }
                valueBox.add(pick, BorderLayout.CENTER);
                usingPick = true;
            } else {
                if (usingPick) {
                    value.setText(String.valueOf(pick.getSelectedItem() == null ? "" : pick.getSelectedItem()));
                }
                valueBox.add(value, BorderLayout.CENTER);
                usingPick = false;
            }
            valueBox.revalidate();
            valueBox.repaint();
        }

        /** 当前这一行填的值（下拉或文本框）。 */
        String valueText() {
            if (usingPick) {
                Object o = pick.getSelectedItem();
                return o == null ? "" : String.valueOf(o).trim();
            }
            return value.getText().trim();
        }

        /** 回填一条已有条件。 */
        void select(SearchRule r) {
            combo.setSelectedIndex(r.or ? 1 : 0);
            for (int i = 0; i < field.getItemCount(); i++) {
                if (field.getItemAt(i).key.equals(r.field)) {
                    field.setSelectedIndex(i);
                    break;
                }
            }
            fillOps();
            fillValue();
            for (int i = 0; i < op.getItemCount(); i++) {
                if (op.getItemAt(i) == r.op) {
                    op.setSelectedIndex(i);
                    break;
                }
            }
            if (usingPick) {
                pick.setSelectedItem(r.value);
            } else {
                value.setText(r.value);
            }
        }
    }

    /** 文档监听器的简写，省掉三个 must-implement。 */
    private static class SimpleDoc implements javax.swing.event.DocumentListener {
        private final Runnable onChange;

        SimpleDoc(Runnable onChange) {
            this.onChange = onChange;
        }

        @Override
        public void insertUpdate(javax.swing.event.DocumentEvent e) {
            onChange.run();
        }

        @Override
        public void removeUpdate(javax.swing.event.DocumentEvent e) {
            onChange.run();
        }

        @Override
        public void changedUpdate(javax.swing.event.DocumentEvent e) {
            onChange.run();
        }
    }
}
