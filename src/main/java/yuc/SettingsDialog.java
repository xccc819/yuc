package yuc;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GraphicsEnvironment;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSpinner;
import javax.swing.JTextArea;
import javax.swing.SpinnerNumberModel;

/**
 * 设置页：收录范围（黑/白名单）+ 响应范围（解析上限、字段上限）。
 * <p>
 * 文案刻意压到最短：标题一行、字段一行提示、示例一行。界面上每个字都要有用。
 */
public final class SettingsDialog {

    private static final long MB = 1024L * 1024;
    private static final java.awt.Color MUTED = new java.awt.Color(0x6b7280);

    private SettingsDialog() {
    }

    /** @return 是否点了保存（保存后调用方负责刷新界面） */
    public static boolean show(Component parent, EndpointStore store) {
        if (GraphicsEnvironment.isHeadless()) {
            return false;   // 自测里没有界面，安静跳过
        }
        Settings set = store.settings();

        JTextArea black = area(set.blacklistText(), 10);
        JTextArea white = area(set.whitelistText(), 4);

        JSpinner parseMb = new JSpinner(new SpinnerNumberModel(
                (int) Math.max(1, Math.min(256, set.maxParseBytes() / MB)), 1, 256, 1));
        JSpinner fields = new JSpinner(new SpinnerNumberModel(
                set.maxResponseFields(), 0, 50000, 50));

        JPanel panel = new JPanel(new BorderLayout(0, 8));
        panel.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4));
        panel.setPreferredSize(new Dimension(720, 466));
        panel.add(content(black, white, parseMb, fields), BorderLayout.CENTER);
        panel.add(toolbar(black), BorderLayout.SOUTH);

        int ok = JOptionPane.showConfirmDialog(parent, panel, "yuc 设置",
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        if (ok != JOptionPane.OK_OPTION) {
            return false;
        }
        set.setRules(black.getText(), white.getText());
        set.setMaxParseBytes(((Number) parseMb.getValue()).longValue() * MB);
        set.setMaxResponseFields(((Number) fields.getValue()).intValue());
        store.saveSettings();
        return true;
    }

    private static JPanel content(JTextArea black, JTextArea white, JSpinner parseMb, JSpinner fields) {
        JPanel root = new JPanel(new GridBagLayout());
        GridBagConstraints c = new GridBagConstraints();
        c.gridx = 0;
        c.weightx = 1;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.insets = new Insets(0, 0, 4, 0);

        c.gridy = 0;
        root.add(head("收录范围", "命中黑名单就不收；白名单留空 = 全收"), c);

        c.gridy++;
        root.add(new JLabel("黑名单"), c);
        c.gridy++;
        c.fill = GridBagConstraints.BOTH;
        c.weighty = 1;
        root.add(scroll(black), c);

        c.gridy++;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.weighty = 0;
        root.add(example("*google.*    *.github.com    /api/admin*    *.internal.corp"), c);

        c.gridy++;
        c.insets = new Insets(10, 0, 4, 0);
        root.add(new JLabel("白名单（留空 = 不过滤）"), c);
        c.gridy++;
        c.insets = new Insets(0, 0, 4, 0);
        c.fill = GridBagConstraints.BOTH;
        c.weighty = 0.6;
        root.add(scroll(white), c);

        c.gridy++;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.weighty = 0;
        root.add(example("*.example.com    /api/*"), c);

        c.gridy++;
        c.insets = new Insets(14, 0, 4, 0);
        root.add(head("响应范围", "控制库和内存的大小"), c);

        c.gridy++;
        c.insets = new Insets(0, 0, 4, 0);
        root.add(row(parseMb, "MB", "正文超过只记长度，不解析字段"), c);

        c.gridy++;
        root.add(row(fields, "个 / 接口", "0 = 不限；只影响之后抓到的数据"), c);

        return root;
    }

    private static JPanel toolbar(JTextArea black) {
        JPanel row = new JPanel(new BorderLayout());
        JButton reset = new JButton("恢复默认黑名单");
        reset.addActionListener(e -> black.setText(String.join("\n", Settings.DEFAULT_BLACKLIST)));
        JPanel right = new JPanel(new FlowLayout(FlowLayout.RIGHT, 0, 0));
        right.add(reset);
        row.add(right, BorderLayout.EAST);
        return row;
    }

    private static JPanel head(String title, String subtitle) {
        JPanel p = new JPanel(new BorderLayout());
        JLabel t = new JLabel(title);
        t.setFont(t.getFont().deriveFont(Font.BOLD, t.getFont().getSize2D() + 1f));
        p.add(t, BorderLayout.WEST);
        JLabel s = new JLabel("  " + subtitle);
        s.setForeground(MUTED);
        p.add(s, BorderLayout.CENTER);
        return p;
    }

    /** 一行示例：等宽小字，灰色。 */
    private static JLabel example(String text) {
        JLabel l = new JLabel("示例　" + text);
        l.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        l.setForeground(MUTED);
        return l;
    }

    private static JPanel row(JSpinner spinner, String unit, String hint) {
        JPanel p = new JPanel(new BorderLayout(8, 0));
        JPanel left = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        spinner.setPreferredSize(new Dimension(84, 24));
        left.add(spinner);
        left.add(new JLabel(unit));
        p.add(left, BorderLayout.WEST);
        JLabel h = new JLabel(hint);
        h.setForeground(MUTED);
        p.add(h, BorderLayout.CENTER);
        return p;
    }

    private static JTextArea area(String text, int rows) {
        JTextArea area = new JTextArea(text == null ? "" : text, rows, 40);
        area.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        area.setLineWrap(false);
        return area;
    }

    private static JScrollPane scroll(JTextArea area) {
        return new JScrollPane(area);
    }
}
