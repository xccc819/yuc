import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.persistence.Persistence;
import burp.api.montoya.persistence.Preferences;
import yuc.Endpoint;
import yuc.EndpointStore;
import yuc.Params;
import yuc.YucPanel;

import javax.swing.SwingUtilities;
import javax.swing.table.DefaultTableModel;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

/**
 * UI 冒烟测试：headless 下把 YucPanel 真造一遍，再喂数据刷新一次表格。
 * 目的只有一个——确认没有构造期空指针、没有布局异常。
 */
public class UiSmoke {

    static int failed = 0;

    public static void main(String[] args) throws Exception {
        System.setProperty("java.awt.headless", "true");

        // 存储目录钉在临时目录：EndpointStore 构造时会读 yuc.dir，否则会去读真实的 ~/yuc-output
        java.io.File tempDir = Files.createTempDirectory("yuc-ui").toFile();
        Preferences prefs = stub(Preferences.class, (n, a) -> {
            if (name_is(n, a, "getString", "yuc.dir")) {
                return tempDir.getAbsolutePath();
            }
            return null;
        });
        Persistence persistence = stub(Persistence.class, (n, a) -> name_is(n, a, "preferences", null) ? prefs : null);
        Logging logging = stub(Logging.class, (n, a) -> null);
        MontoyaApi api = stub(MontoyaApi.class, (n, a) -> {
            switch (n) {
                case "persistence": return persistence;
                case "logging": return logging;
                default: return null;
            }
        });

        EndpointStore store = new EndpointStore(api);
        store.setRecording(true);

        YucPanel panel = new YucPanel(api, store);
        check("面板构造成功", panel != null);

        store.add(new Endpoint("GET", "https", "h5.aep.com.cn", 443, "/api/v1/list",
                "https://h5.aep.com.cn/api/v1/list?page=1", "Proxy",
                List.<String[]>of(new String[]{"page", "1"}), new ArrayList<String[]>(),
                "application/json", "{\"q\":1}", "application/json",
                "{\"code\":0,\"data\":{\"list\":[{\"id\":1}]}}", 200, 100));
        store.add(new Endpoint("POST", "https", "api.example.com", 443, "/v1/user/detail",
                "https://api.example.com/v1/user/detail", "Repeater",
                new ArrayList<String[]>(), new ArrayList<String[]>(),
                "application/json", "{\"id\":10086,\"items\":[{\"sku\":\"a\"}]}", "application/json",
                "{\"code\":0,\"data\":{\"name\":\"张三\"}}", 200, 90));

        SwingUtilities.invokeAndWait(() -> invoke(panel, "refreshAll"));

        DefaultTableModel paths = (DefaultTableModel) field(panel, "pathModel");
        DefaultTableModel params = (DefaultTableModel) field(panel, "paramModel");
        check("路径表有数据（全部域名视图）", paths.getRowCount() == 2);
        check("参数表有数据", params.getRowCount() > 0);

        // 参数表只显示最后一层 key
        boolean anyDotted = false;
        for (int i = 0; i < params.getRowCount(); i++) {
            String name = String.valueOf(params.getValueAt(i, 0));
            if (name.contains(".") || name.contains("[]")) {
                anyDotted = true;
            }
        }
        check("参数表只显示 key（不带层级）", !anyDotted);

        // 路径按「从左 1 段」截断展示
        SwingUtilities.invokeAndWait(() -> {
            ((javax.swing.JComboBox<?>) field(panel, "pathMode")).setSelectedIndex(1);
            ((javax.swing.JSpinner) field(panel, "pathDepth")).setValue(1);
            invoke(panel, "applyFilter");
        });
        String shown = String.valueOf(paths.getValueAt(0, 0));
        check("从左 1 段 → /api", "/api".equals(shown));

        // 再切「从右 1 段」
        SwingUtilities.invokeAndWait(() -> {
            ((javax.swing.JComboBox<?>) field(panel, "pathMode")).setSelectedIndex(2);
            ((javax.swing.JSpinner) field(panel, "pathDepth")).setValue(1);
            invoke(panel, "applyFilter");
        });
        String right = String.valueOf(paths.getValueAt(0, 0));
        check("从右 1 段 → /list", "/list".equals(right));

        System.out.println("[ui] 路径行数=" + paths.getRowCount() + " 参数行数=" + params.getRowCount()
                + " 截断后首行=" + right
                + " 状态=" + ((javax.swing.JLabel) field(panel, "statsLabel")).getText());

        // ---------------------------------------------------- 参数来源多选筛选
        int baseParamRows = params.getRowCount();
        @SuppressWarnings("unchecked")
        java.util.Set<String> sources = (java.util.Set<String>) field(panel, "paramSources");
        SwingUtilities.invokeAndWait(() -> {
            sources.add("查询");
            invoke(panel, "refreshParams");
        });
        boolean onlyQuery = params.getRowCount() > 0;
        for (int i = 0; i < params.getRowCount(); i++) {
            if (!"查询".equals(String.valueOf(params.getValueAt(i, 1)))) {
                onlyQuery = false;
            }
        }
        check("来源只勾查询 → 只剩查询参数", onlyQuery && params.getRowCount() == 1);
        check("来源按钮显示当前筛选",
                ((javax.swing.JButton) field(panel, "paramSourceButton")).getText().contains("查询"));

        // 多选：查询 + 响应，两类同时出现（单选下拉做不到这点）
        SwingUtilities.invokeAndWait(() -> {
            sources.add("响应");
            invoke(panel, "refreshParams");
        });
        boolean hasQuery = false;
        boolean hasResponse = false;
        for (int i = 0; i < params.getRowCount(); i++) {
            String where = String.valueOf(params.getValueAt(i, 1));
            hasQuery |= "查询".equals(where);
            hasResponse |= "响应".equals(where);
            check("多选后不该出现未勾选的来源（" + where + "）",
                    "查询".equals(where) || "响应".equals(where));
        }
        check("查询 + 响应可同时显示", hasQuery && hasResponse);

        // 重置参数筛选 → 恢复到筛选前
        SwingUtilities.invokeAndWait(() -> invoke(panel, "resetParamFilters"));
        check("参数重置 → 行数恢复", params.getRowCount() == baseParamRows);
        check("参数重置 → 来源回到全部",
                sources.isEmpty()
                        && "来源：全部".equals(((javax.swing.JButton) field(panel, "paramSourceButton")).getText()));

        // ------------------------------------------ 参数多选 → 复制为 payload
        javax.swing.JTable ptable = (javax.swing.JTable) field(panel, "paramTable");
        SwingUtilities.invokeAndWait(() -> {
            if (ptable.getRowCount() >= 2) {
                ptable.setRowSelectionInterval(0, 1);
            }
        });
        @SuppressWarnings("unchecked")
        List<String[]> picked = (List<String[]>) call(panel, "selectedParamPairs");
        check("选中 2 行 → 取到 2 组参数", picked.size() == 2);
        check("payload 取的是完整值（不是截断后的展示值）",
                picked.stream().allMatch(p -> p[1].equals(p[1].replace("…", ""))));
        check("多选 raw 用 & 拼接", yuc.Payload.raw(picked).contains("&") || picked.size() == 1);
        SwingUtilities.invokeAndWait(() -> ptable.clearSelection());
        @SuppressWarnings("unchecked")
        List<String[]> all = (List<String[]>) call(panel, "selectedParamPairs");
        check("没选中 → payload 取全部可见行", all.size() == params.getRowCount());

        // -------------------------------------------- 参数右键 → 反查来源接口
        @SuppressWarnings("unchecked")
        List<Params.ParamStat> rows = (List<Params.ParamStat>) field(panel, "paramRows");
        Params.ParamStat page = null;
        for (Params.ParamStat st : rows) {
            if (st.name.equals("page") && st.where.equals("查询")) {
                page = st;
            }
        }
        check("paramRows 里能找到 page", page != null);
        Params.ParamStat target = page;
        SwingUtilities.invokeAndWait(() -> invoke1(panel, "scopeToParam", Params.ParamStat.class, target));
        check("只看用到 page 的接口 → 路径只剩 1 行", paths.getRowCount() == 1);
        check("路径表收敛到 /api/v1/list", "/list".equals(String.valueOf(paths.getValueAt(0, 0))));
        check("状态栏标注了参数约束",
                String.valueOf(((javax.swing.JLabel) field(panel, "pathCount")).getText()).contains("参数 page"));

        // 重置路径筛选 → 恢复全部接口，且约束一起清掉
        SwingUtilities.invokeAndWait(() -> invoke(panel, "resetPathFilters"));
        check("路径重置 → 行数恢复", paths.getRowCount() == 2);
        check("路径重置 → 去掉参数约束",
                !String.valueOf(((javax.swing.JLabel) field(panel, "pathCount")).getText()).contains("参数 "));

        // ------------------------------------------------ 三级域名树 + 搜索
        javax.swing.tree.DefaultMutableTreeNode root =
                (javax.swing.tree.DefaultMutableTreeNode) field(panel, "rootNode");
        check("左侧树按根域分组（2 组）", root.getChildCount() == 2);
        javax.swing.tree.DefaultMutableTreeNode g0 =
                (javax.swing.tree.DefaultMutableTreeNode) root.getChildAt(0);
        check("分组下面挂着具体域名", g0.getChildCount() == 1);

        javax.swing.JTree tree = (javax.swing.JTree) field(panel, "domainTree");
        javax.swing.JTextField search = (javax.swing.JTextField) field(panel, "domainSearch");
        SwingUtilities.invokeAndWait(() -> search.setText("h5."));
        check("搜索后只剩 1 组", root.getChildCount() == 1);
        SwingUtilities.invokeAndWait(() -> search.setText(""));
        check("清空搜索后恢复 2 组", root.getChildCount() == 2);

        SwingUtilities.invokeAndWait(() -> tree.setSelectionPath(new javax.swing.tree.TreePath(
                ((javax.swing.tree.DefaultMutableTreeNode) root.getChildAt(0)).getPath())));
        check("点分组节点能看到组内接口", paths.getRowCount() == 1);

        SwingUtilities.invokeAndWait(() -> tree.setSelectionRow(0));
        check("点「全部」回到所有接口", paths.getRowCount() == 2);

        // -------------------------------------- 同一接口多长度档
        store.add(new Endpoint("GET", "https", "h5.aep.com.cn", 443, "/api/v1/list",
                "https://h5.aep.com.cn/api/v1/list?page=1", "Proxy",
                List.<String[]>of(new String[]{"page", "1"}), new ArrayList<String[]>(),
                "application/json", "", "application/json",
                "{\"code\":0,\"data\":{\"list\":[{\"id\":1},{\"id\":2}]}}", 200, 5000));
        SwingUtilities.invokeAndWait(() -> invoke(panel, "refreshAll"));
        check("同接口多档不新增路径行", paths.getRowCount() == 2);

        int listRow = -1;
        for (int i = 0; i < paths.getRowCount(); i++) {
            if (String.valueOf(paths.getValueAt(i, 1)).equals("GET")) {
                listRow = i;
            }
        }
        check("能在路径表里找到那个接口", listRow >= 0);
        String byteCell = String.valueOf(paths.getValueAt(listRow, 3));
        check("响应字节列标出档数（" + byteCell + "）", byteCell.contains("等2档"));

        int targetRow = listRow;
        javax.swing.JTable pathTbl = (javax.swing.JTable) field(panel, "pathTable");
        SwingUtilities.invokeAndWait(() -> pathTbl.setRowSelectionInterval(targetRow, targetRow));
        javax.swing.JPopupMenu menu = (javax.swing.JPopupMenu) call(panel, "pathPopup");
        javax.swing.JMenu byLen = null;
        for (java.awt.Component c : menu.getComponents()) {
            if (c instanceof javax.swing.JMenu && ((javax.swing.JMenu) c).getText().startsWith("按长度发送")) {
                byLen = (javax.swing.JMenu) c;
            }
        }
        check("右键有「按长度发送到 Repeater」子菜单", byLen != null);
        check("子菜单列出 2 档", byLen != null && byLen.getItemCount() == 2);
        check("最长那档排第一并标注",
                byLen != null && byLen.getItem(0).getText().contains("5000")
                        && byLen.getItem(0).getText().contains("最长"));
        check("每档都有悬停说明（带长度）",
                byLen != null && byLen.getItem(0).getToolTipText().contains("5000")
                        && byLen.getItem(1).getToolTipText().contains("100"));

        javax.swing.JButton hb = (javax.swing.JButton) field(panel, "headerButton");
        check("请求头按钮存在", hb != null && hb.getText().startsWith("请求头"));

        // ---------------------------------- 搜索：忽略大小写 / 反向 / 正则
        SwingUtilities.invokeAndWait(() -> {
            ((javax.swing.JComboBox<?>) field(panel, "pathMode")).setSelectedIndex(0);
            ((javax.swing.JTextField) field(panel, "pathFilter")).setText("list");
            invoke(panel, "applyFilter");
        });
        check("普通过滤只留 1 条", paths.getRowCount() == 1);

        SwingUtilities.invokeAndWait(() -> {
            ((javax.swing.JCheckBox) field(panel, "pathInvert")).setSelected(true);
            invoke(panel, "applyFilter");
        });
        check("反向过滤只剩不匹配的那条",
                paths.getRowCount() == 1 && !String.valueOf(paths.getValueAt(0, 0)).contains("list"));

        SwingUtilities.invokeAndWait(() -> {
            ((javax.swing.JTextField) field(panel, "pathFilter")).setText("^/api/.*list");
            ((javax.swing.JCheckBox) field(panel, "pathRegex")).setSelected(true);
            invoke(panel, "applyFilter");
        });
        check("正则 + 反向：命中被排除", paths.getRowCount() == 1);

        SwingUtilities.invokeAndWait(() -> {
            ((javax.swing.JCheckBox) field(panel, "pathRegex")).setSelected(false);
            ((javax.swing.JCheckBox) field(panel, "pathInvert")).setSelected(false);
            ((javax.swing.JTextField) field(panel, "pathFilter")).setText("LIST");
            invoke(panel, "applyFilter");
        });
        check("忽略大小写默认勾着 → LIST 能命中 list", paths.getRowCount() == 1);

        // 高级搜索：列 + 关系 + 值
        SwingUtilities.invokeAndWait(() -> {
            ((javax.swing.JTextField) field(panel, "pathFilter")).setText("");
            set(panel, "pathRules", new ArrayList<>(List.of(
                    new yuc.SearchRule("path", yuc.SearchRule.Op.CONTAINS, "list", false))));
            invoke(panel, "updateAdvancedButtons");
            invoke(panel, "applyFilter");
        });
        check("高级搜索（路径 包含 list）生效", paths.getRowCount() == 1);
        check("高级按钮标出条件条数",
                ((javax.swing.JButton) field(panel, "pathAdvancedButton")).getText().equals("高级(1)"));

        SwingUtilities.invokeAndWait(() -> {
            set(panel, "pathRules", new ArrayList<>(List.of(
                    new yuc.SearchRule("path", yuc.SearchRule.Op.CONTAINS, "list", false),
                    new yuc.SearchRule("method", yuc.SearchRule.Op.EQUALS, "POST", false))));
            invoke(panel, "applyFilter");
        });
        check("高级搜索两条「且」不成立", paths.getRowCount() == 0);

        SwingUtilities.invokeAndWait(() -> {
            // 第一条否掉 list（GET），第二条用「或」把它捡回来 → 两条都留
            set(panel, "pathRules", new ArrayList<>(List.of(
                    new yuc.SearchRule("method", yuc.SearchRule.Op.EQUALS, "POST", false),
                    new yuc.SearchRule("path", yuc.SearchRule.Op.CONTAINS, "list", true))));
            invoke(panel, "applyFilter");
        });
        check("高级搜索「或」把第一条否掉的行也留下", paths.getRowCount() == 2);

        SwingUtilities.invokeAndWait(() -> {
            set(panel, "pathRules", new ArrayList<>(List.of(
                    new yuc.SearchRule("bytes", yuc.SearchRule.Op.GT, "1000", false),
                    new yuc.SearchRule("path", yuc.SearchRule.Op.CONTAINS, "list", false))));
            invoke(panel, "applyFilter");
        });
        check("数字列「大于」生效（5000 那档 > 1000 且命中 list）", paths.getRowCount() == 1);

        SwingUtilities.invokeAndWait(() -> invoke(panel, "resetPathFilters"));
        check("重置同时清掉高级条件", paths.getRowCount() == 2
                && ((javax.swing.JButton) field(panel, "pathAdvancedButton")).getText().equals("高级"));

        // 参数搜索也有一套同样的开关（注意此刻参数表只统计选中的那个接口，别拿早先的行数当基准）
        int paramBase2 = params.getRowCount();
        SwingUtilities.invokeAndWait(() -> {
            ((javax.swing.JTextField) field(panel, "paramFilter")).setText("PAGE");
            invoke(panel, "refreshParams");
        });
        boolean upperHit = params.getRowCount() > 0;
        for (int i = 0; i < params.getRowCount(); i++) {
            if (!String.valueOf(params.getValueAt(i, 0)).contains("page")) {
                upperHit = false;
            }
        }
        check("参数搜索忽略大小写", upperHit && params.getRowCount() == 1);

        SwingUtilities.invokeAndWait(() -> {
            ((javax.swing.JCheckBox) field(panel, "paramInvert")).setSelected(true);
            invoke(panel, "refreshParams");
        });
        boolean noPage = true;
        for (int i = 0; i < params.getRowCount(); i++) {
            if ("page".equals(String.valueOf(params.getValueAt(i, 0)))) {
                noPage = false;
            }
        }
        check("参数反向过滤 → page 被排除", noPage && params.getRowCount() == paramBase2 - 1);

        SwingUtilities.invokeAndWait(() -> invoke(panel, "resetParamFilters"));
        check("参数重置清掉反向与过滤", params.getRowCount() == paramBase2
                && !((javax.swing.JCheckBox) field(panel, "paramInvert")).isSelected());

        // -------------------------------------------- 右键删除（无界面时不许真删）
        SwingUtilities.invokeAndWait(() -> pathTbl.setRowSelectionInterval(0, 0));
        @SuppressWarnings("unchecked")
        List<Endpoint> checked = (List<Endpoint>) call(panel, "checkedEndpoints");
        check("checkedEndpoints 只取选中的", checked.size() == 1);
        javax.swing.JPopupMenu delMenu = (javax.swing.JPopupMenu) call(panel, "pathPopup");
        boolean hasDelete = false;
        for (java.awt.Component c : delMenu.getComponents()) {
            if (c instanceof javax.swing.JMenuItem && ((javax.swing.JMenuItem) c).getText().startsWith("删除")) {
                hasDelete = true;
            }
        }
        check("右键有「删除该路径」", hasDelete);
        SwingUtilities.invokeAndWait(() -> invoke(panel, "deletePaths"));
        check("headless 下确认框被视为拒绝，不会静默删除", store.endpointCount() == 2);

        // ------------------------------------------------ 导入 JSON
        String template = "{\"base\":{\"scheme\":\"https\",\"host\":\"imp.example.com\",\"port\":443},"
                + "\"items\":[{\"id\":\"imp\",\"method\":\"GET\",\"uri\":\"/v1/imp\","
                + "\"params\":[{\"in\":\"query\",\"name\":\"q\",\"value\":\"1\"}]}]}";
        List<Endpoint> imported = yuc.TemplateImport.parse(template, "导入");
        String[] msg = new String[1];
        SwingUtilities.invokeAndWait(() -> msg[0] = String.valueOf(
                call2(panel, "doImport", List.class, String.class, imported, "测试")));
        check("导入摘要可读（" + msg[0] + "）", msg[0].contains("新增 1 个"));
        check("导入后路径表多一行", paths.getRowCount() == 3);
        boolean templateCell = false;
        for (int i = 0; i < paths.getRowCount(); i++) {
            if ("模板".equals(String.valueOf(paths.getValueAt(i, 3)))
                    && "/v1/imp".equals(String.valueOf(paths.getValueAt(i, 0)))) {
                templateCell = true;
            }
        }
        check("导入的接口响应字节列显示「模板」", templateCell);

        // ------------------------------------- IP 按 /24 归组 + 分组默认收起
        store.add(new Endpoint("GET", "http", "10.2.3.4", 8080, "/svc/ping",
                "http://10.2.3.4:8080/svc/ping", "Proxy",
                new ArrayList<String[]>(), new ArrayList<String[]>(),
                null, "", "application/json", "{\"ok\":1}", 200, 90));
        SwingUtilities.invokeAndWait(() -> invoke(panel, "refreshAll"));
        check("IP 单独成一组（共 3 组）", root.getChildCount() == 3);
        boolean cidr = false;
        for (int i = 0; i < root.getChildCount(); i++) {
            if (String.valueOf(root.getChildAt(i)).contains("10.2.3.0/24")) {
                cidr = true;
            }
        }
        check("IP 分组名是 10.2.3.0/24", cidr);

        check("根节点展开着", tree.isExpanded(new javax.swing.tree.TreePath(root.getPath())));
        boolean anyOpen = false;
        for (int i = 0; i < root.getChildCount(); i++) {
            if (tree.isExpanded(new javax.swing.tree.TreePath(
                    ((javax.swing.tree.DefaultMutableTreeNode) root.getChildAt(i)).getPath()))) {
                anyOpen = true;
            }
        }
        check("分组默认收起", !anyOpen);

        javax.swing.tree.DefaultMutableTreeNode firstGroup =
                (javax.swing.tree.DefaultMutableTreeNode) root.getChildAt(0);
        String firstGroupName = String.valueOf(firstGroup);
        SwingUtilities.invokeAndWait(() -> tree.expandPath(new javax.swing.tree.TreePath(firstGroup.getPath())));
        check("点开后展开", tree.isExpanded(new javax.swing.tree.TreePath(firstGroup.getPath())));
        SwingUtilities.invokeAndWait(() -> invoke(panel, "refreshAll"));
        javax.swing.tree.DefaultMutableTreeNode again =
                (javax.swing.tree.DefaultMutableTreeNode) root.getChildAt(0);
        check("刷新重建后仍记住展开状态（" + firstGroupName + "）",
                tree.isExpanded(new javax.swing.tree.TreePath(again.getPath())));

        // ------------------------------------------------ 颜色标记：置顶 / 排序 / 筛选
        SwingUtilities.invokeAndWait(() -> invoke(panel, "refreshAll"));
        int total = paths.getRowCount();
        check("当前一共 " + total + " 个接口", total == 4);

        Endpoint ping = store.endpoints("10.2.3.4:8080").get(0);
        String pingKey = ping.key;
        String pingDomain = ping.domainKey();
        check("IP 那个接口不是第一行", !endpointAt(panel, 0).key.equals(pingKey));

        check("上色成功", store.marks().set(yuc.Marks.PATH, pingDomain, pingKey, 1));
        SwingUtilities.invokeAndWait(() -> invoke(panel, "applyFilter"));
        check("上色不改变行数", paths.getRowCount() == total);
        check("有色行被置顶", endpointAt(panel, 0).key.equals(pingKey));

        // 渲染器真的把底色改了：第一行被染过，第二行还是表格底色
        java.awt.Component cell = pathTbl.getCellRenderer(0, 0).getTableCellRendererComponent(
                pathTbl, pathTbl.getValueAt(0, 0), false, false, 0, 0);
        check("有色行底色被染过", !cell.getBackground().equals(pathTbl.getBackground()));
        java.awt.Component plain = pathTbl.getCellRenderer(1, 0).getTableCellRendererComponent(
                pathTbl, pathTbl.getValueAt(1, 0), false, false, 1, 0);
        check("没标色的行仍是表格底色", plain.getBackground().equals(pathTbl.getBackground()));

        // 右键菜单：6 个颜色 + 清除
        SwingUtilities.invokeAndWait(() -> pathTbl.setRowSelectionInterval(0, 0));
        javax.swing.JPopupMenu pm = (javax.swing.JPopupMenu) call(panel, "pathPopup");
        javax.swing.JMenu colorMenu = null;
        for (java.awt.Component c : pm.getComponents()) {
            if (c instanceof javax.swing.JMenu
                    && String.valueOf(((javax.swing.JMenu) c).getText()).startsWith("标记颜色")) {
                colorMenu = (javax.swing.JMenu) c;
            }
        }
        check("路径右键有「标记颜色」", colorMenu != null);
        int colorItems = 0;
        boolean hasClear = false;
        if (colorMenu != null) {
            for (java.awt.Component c : colorMenu.getMenuComponents()) {
                if (c instanceof javax.swing.JMenuItem) {
                    if (String.valueOf(((javax.swing.JMenuItem) c).getText()).startsWith("清除颜色")) {
                        hasClear = true;
                    } else {
                        colorItems++;
                    }
                }
            }
        }
        check("6 个颜色可选", colorItems == yuc.Marks.NAMES.length);
        check("有「清除颜色」", hasClear);

        // 按颜色排序（只有高级里能改）：直接塞字段，等价于在弹框里选
        String listKey = store.endpoints("h5.aep.com.cn:443").get(0).key;
        store.marks().set(yuc.Marks.PATH, "h5.aep.com.cn:443", listKey, 5);
        set(panel, "pathSort", sortOf("ASC"));
        SwingUtilities.invokeAndWait(() -> invoke(panel, "applyFilter"));
        check("颜色升序：红（1）在蓝（5）前", endpointAt(panel, 0).key.equals(pingKey)
                && endpointAt(panel, 1).key.equals(listKey));
        check("升序时无色垫底", store.marks().color(yuc.Marks.PATH,
                endpointAt(panel, total - 1).domainKey(), endpointAt(panel, total - 1).key) == 0);

        set(panel, "pathSort", sortOf("DESC"));
        SwingUtilities.invokeAndWait(() -> invoke(panel, "applyFilter"));
        check("颜色降序：蓝在红前", endpointAt(panel, 0).key.equals(listKey)
                && endpointAt(panel, 1).key.equals(pingKey));

        // 重置：排序回默认，有色照样置顶
        SwingUtilities.invokeAndWait(() -> invoke(panel, "resetPathFilters"));
        check("重置后按钮不带排序标记",
                ((javax.swing.JButton) field(panel, "pathAdvancedButton")).getText().equals("高级"));
        check("重置后仍是「有色置顶」（不按色号）", paths.getRowCount() == total
                && store.marks().color(yuc.Marks.PATH, endpointAt(panel, 0).domainKey(),
                        endpointAt(panel, 0).key) > 0
                && store.marks().color(yuc.Marks.PATH, endpointAt(panel, 1).domainKey(),
                        endpointAt(panel, 1).key) > 0);

        // 高级条件里能按颜色筛
        SwingUtilities.invokeAndWait(() -> {
            set(panel, "pathRules", java.util.List.of(
                    new yuc.SearchRule("color", yuc.SearchRule.Op.EQUALS, "红", false)));
            invoke(panel, "applyFilter");
        });
        check("高级条件「颜色 等于 红」只剩 1 行", paths.getRowCount() == 1);
        SwingUtilities.invokeAndWait(() -> invoke(panel, "resetPathFilters"));

        // 参数表同款：给 page 标蓝，置顶
        store.marks().set(yuc.Marks.PARAM, "", yuc.Marks.paramTarget("查询", "page"), 5);
        SwingUtilities.invokeAndWait(() -> invoke(panel, "refreshParams"));
        check("参数表也把有色行置顶",
                params.getRowCount() > 0 && String.valueOf(params.getValueAt(0, 0)).equals("page"));

        javax.swing.JTable paramTbl = (javax.swing.JTable) field(panel, "paramTable");
        SwingUtilities.invokeAndWait(() -> paramTbl.setRowSelectionInterval(0, 0));
        javax.swing.JPopupMenu ppm = (javax.swing.JPopupMenu) call(panel, "paramPopup");
        boolean paramColorMenu = false;
        for (java.awt.Component c : ppm.getComponents()) {
            if (c instanceof javax.swing.JMenu
                    && String.valueOf(((javax.swing.JMenu) c).getText()).startsWith("标记颜色")) {
                paramColorMenu = true;
            }
        }
        check("参数右键也有「标记颜色」", paramColorMenu);

        // ------------------------------------------------ 复制参数值 / 数组容器行
        boolean copyValueItem = false;
        for (java.awt.Component c : ppm.getComponents()) {
            if (c instanceof javax.swing.JMenuItem && "复制参数值".equals(((javax.swing.JMenuItem) c).getText())) {
                copyValueItem = true;
            }
        }
        check("参数右键有「复制参数值」", copyValueItem);
        check("复制的是值本身（选中 page）", "1".equals(call(panel, "paramValues")));

        @SuppressWarnings("unchecked")
        java.util.List<yuc.Params.ParamStat> prs =
                (java.util.List<yuc.Params.ParamStat>) field(panel, "paramRows");
        yuc.Params.ParamStat items = prs.stream().filter(s -> s.name.equals("items")).findFirst().orElse(null);
        check("数组参数 items 自己也占一行", items != null);
        check("items 的值 = 元素的键清单", items != null && items.payload.equals("[sku]"));
        yuc.Params.ParamStat dataObj = prs.stream()
                .filter(s -> s.fullPath.equals("data") && s.where.equals("响应")).findFirst().orElse(null);
        check("对象容器也进参数表（data = {list}）", dataObj != null && dataObj.payload.equals("{list}"));

        // ------------------------------------------------ 记录类型按钮
        check("默认只记 JSON", store.recordTypes().equals(java.util.Set.of("JSON")));
        javax.swing.JButton typeBtn = (javax.swing.JButton) field(panel, "typeButton");
        check("按钮显示「类型：JSON」", typeBtn.getText().equals("类型：JSON"));
        store.setRecordTypes(List.of("JSON", "HTML"));
        SwingUtilities.invokeAndWait(() -> invoke(panel, "updateTypeButton"));
        check("勾上 HTML 后按钮变成 JSON+HTML", typeBtn.getText().equals("类型：JSON+HTML"));
        SwingUtilities.invokeAndWait(() -> invoke(panel, "editRecordTypes"));
        check("headless 下打开弹框不抛异常（打日志跳过）",
                store.recordTypes().contains("HTML"));
        store.setRecordTypes(List.of("JSON"));

        System.out.println(failed == 0 ? "UI PASS" : "UI FAILED: " + failed);
        if (failed > 0) {
            System.exit(1);
        }
    }

    @SuppressWarnings("unchecked")
    static <T> T stub(Class<T> iface, Handler handler) {
        InvocationHandler ih = (proxy, method, args) -> {
            String name = method.getName();
            if (name.equals("toString")) {
                return "stub:" + iface.getSimpleName();
            }
            if (name.equals("hashCode")) {
                return System.identityHashCode(proxy);
            }
            if (name.equals("equals")) {
                return proxy == args[0];
            }
            Object v = handler.handle(name, args);
            if (v == null && method.getReturnType().isPrimitive()) {
                Class<?> t = method.getReturnType();
                if (t == boolean.class) {
                    return false;
                }
                if (t == int.class) {
                    return 0;
                }
                if (t == long.class) {
                    return 0L;
                }
                if (t == short.class) {
                    return (short) 0;
                }
                if (t == byte.class) {
                    return (byte) 0;
                }
                if (t == char.class) {
                    return (char) 0;
                }
                return 0.0;
            }
            return v;
        };
        return (T) Proxy.newProxyInstance(UiSmoke.class.getClassLoader(), new Class<?>[]{iface}, ih);
    }

    interface Handler {
        Object handle(String method, Object[] args);
    }

    /** method 名匹配，且第一个参数等于 arg0（arg0 为 null 时只看方法名）。 */
    static boolean name_is(String method, Object[] args, String methodName, String arg0) {
        if (!method.equals(methodName)) {
            return false;
        }
        if (arg0 == null) {
            return true;
        }
        return args != null && args.length > 0 && arg0.equals(args[0]);
    }

    static Object field(Object target, String name) {
        try {
            Field f = target.getClass().getDeclaredField(name);
            f.setAccessible(true);
            return f.get(target);
        } catch (ReflectiveOperationException e) {
            throw new RuntimeException(e);
        }
    }

    static void invoke(Object target, String name) {
        try {
            Method m = target.getClass().getDeclaredMethod(name);
            m.setAccessible(true);
            m.invoke(target);
        } catch (ReflectiveOperationException e) {
            throw new RuntimeException(e);
        }
    }

    static Object call(Object target, String name) {
        try {
            Method m = target.getClass().getDeclaredMethod(name);
            m.setAccessible(true);
            return m.invoke(target);
        } catch (ReflectiveOperationException e) {
            throw new RuntimeException(e);
        }
    }

    static void invoke1(Object target, String name, Class<?> type, Object arg) {
        try {
            Method m = target.getClass().getDeclaredMethod(name, type);
            m.setAccessible(true);
            m.invoke(target, arg);
        } catch (ReflectiveOperationException e) {
            throw new RuntimeException(e);
        }
    }

    static Object call2(Object target, String name, Class<?> t1, Class<?> t2, Object a1, Object a2) {
        try {
            Method m = target.getClass().getDeclaredMethod(name, t1, t2);
            m.setAccessible(true);
            return m.invoke(target, a1, a2);
        } catch (ReflectiveOperationException e) {
            throw new RuntimeException(e);
        }
    }

    static void set(Object target, String name, Object value) {
        try {
            Field f = target.getClass().getDeclaredField(name);
            f.setAccessible(true);
            f.set(target, value);
        } catch (ReflectiveOperationException e) {
            throw new RuntimeException(e);
        }
    }

    /** 路径表第 modelRow 行对应的接口：直接读 panel 内部的 visible 列表，比猜文字可靠。 */
    static Endpoint endpointAt(Object panel, int modelRow) {
        java.util.List<?> vis = (java.util.List<?>) field(panel, "visible");
        Object row = vis.get(modelRow);
        return (Endpoint) field(row, "ep");
    }

    /** 拿排序枚举的某个档（它是 YucPanel 的私有内部枚举，测试里只能反射取）。 */
    static Object sortOf(String name) {
        try {
            Class<?> c = Class.forName("yuc.YucPanel$ColorSort");
            Method m = c.getMethod("valueOf", String.class);
            m.setAccessible(true);
            return m.invoke(null, name);
        } catch (ReflectiveOperationException e) {
            throw new RuntimeException(e);
        }
    }

    static void check(String name, boolean ok) {
        if (!ok) {
            failed++;
            System.out.println("  FAIL " + name);
        } else {
            System.out.println("  PASS " + name);
        }
    }
}
