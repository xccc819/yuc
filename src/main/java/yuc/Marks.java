package yuc;

import java.awt.Color;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 行颜色标记：路径表给接口上色、参数表给参数上色，用来标「重点 / 已测过 / 有问题」。
 * <p>
 * <b>为什么单独一张表</b>：{@code Db.saveDomain} 是整域名重写（先删后插，见 Db 的注释），
 * 颜色要是挂在 {@code endpoints} 那一行上，每落盘一次就跟着没了。所以标记存在自己的
 * {@code marks} 表里，跟样本数据的写入互不干扰。
 * <p>
 * <b>键怎么定</b>：
 * <ul>
 *   <li>路径：{@code dedupe_key}（方法 + 协议 + 域名端口 + 路径 + 查询名），scope 记域名端口，
 *       删域名时一次收干净。同一个接口重新抓到时 key 不变，颜色自己就回来了。</li>
 *   <li>参数：{@code 位置\0名字}，<b>故意不带域名</b>——参数表本来就是跨接口 / 跨域名的聚合视图，
 *       「page 标红」是全局认知；带上域名反而同一行在不同视图里颜色不一致。</li>
 * </ul>
 * 落库是同步的：点一下改一行，SQLite 单行写是亚毫秒级，不值得为它再摆一套防抖。
 */
public final class Marks {

    /** 路径标记的种类键。 */
    public static final String PATH = "path";
    /** 参数标记的种类键。 */
    public static final String PARAM = "param";

    /** 可选颜色，顺序就是「按颜色排序」的顺序：红 → 紫。下标 1 起，0 表示没标。 */
    public static final String[] NAMES = {"红", "橙", "黄", "绿", "蓝", "紫"};

    /** 菜单色块用的纯色。 */
    private static final int[] RGB = {0xE53935, 0xF57C00, 0xF9A825, 0x43A047, 0x1E88E5, 0x8E24AA};

    /** 行底色只掺这么多纯色，剩下的留给表格底色——保证文字始终看得清。 */
    private static final double TINT = 0.22;

    private final Map<String, Integer> marks = new LinkedHashMap<>();
    private final Object lock = new Object();
    private volatile Db db;

    /** 接上数据库并把已有标记读回内存；{@code db} 为 null 表示纯内存（库打不开时的降级）。 */
    void attach(Db db) {
        synchronized (lock) {
            marks.clear();
            this.db = db;
            if (db == null) {
                return;
            }
            try {
                for (String[] row : db.loadMarks()) {
                    if (row.length < 4 || row[3] == null) {
                        continue;
                    }
                    try {
                        marks.put(key(row[0], row[1], row[2]), Integer.parseInt(row[3]));
                    } catch (NumberFormatException ignored) {
                        // 脏数据跳过就行，别让整个加载挂掉
                    }
                }
            } catch (RuntimeException ignored) {
                // 读不到就当没有标记：颜色是锦上添花，不能影响主流程
            }
        }
    }

    /** 当前的色号（1..6），没标是 0。 */
    public int color(String kind, String scope, String target) {
        if (target == null || target.isEmpty()) {
            return 0;
        }
        synchronized (lock) {
            Integer v = marks.get(key(kind, scope, target));
            return v == null ? 0 : v;
        }
    }

    /** 这个目标的颜色名（红/橙/…），没标返回空串——高级搜索按颜色筛的就是它。 */
    public String colorName(String kind, String scope, String target) {
        return name(color(kind, scope, target));
    }

    /**
     * 设颜色（1..6）或清除（0）。
     *
     * @return 是否真的变了（颜色没变就不必重排表格）
     */
    public boolean set(String kind, String scope, String target, int color) {
        if (target == null || target.isEmpty()) {
            return false;
        }
        int next = color < 0 || color > NAMES.length ? 0 : color;
        String k = key(kind, scope, target);
        synchronized (lock) {
            Integer old = marks.get(k);
            if ((old == null ? 0 : old) == next) {
                return false;
            }
            if (next == 0) {
                marks.remove(k);
            } else {
                marks.put(k, next);
            }
            Db d = db;
            if (d != null) {
                try {
                    if (next == 0) {
                        d.deleteMark(kind, scope, target);
                    } else {
                        d.saveMark(kind, scope, target, next);
                    }
                } catch (RuntimeException ignored) {
                    // 落库失败也保留内存里的颜色：界面能看见，下次再点一次就补上了
                }
            }
            return true;
        }
    }

    /** 删域名时把它的路径标记一起收掉（参数标记是跨域名的，不动）。 */
    void forgetDomain(String domainKey) {
        synchronized (lock) {
            marks.keySet().removeIf(k -> k.startsWith(PATH + '\u0000' + domainKey + '\u0000'));
            Db d = db;
            if (d != null) {
                try {
                    d.deleteMarks(PATH, domainKey);
                } catch (RuntimeException ignored) {
                    // 同上，删不干净也不会让域名删不掉
                }
            }
        }
    }

    /** 清空全部标记。 */
    void clear() {
        synchronized (lock) {
            marks.clear();
            Db d = db;
            if (d != null) {
                try {
                    d.deleteAllMarks();
                } catch (RuntimeException ignored) {
                    // 忽略
                }
            }
        }
    }

    /** 标了颜色的总数（状态栏用）。 */
    public int size() {
        synchronized (lock) {
            return marks.size();
        }
    }

    private static String key(String kind, String scope, String target) {
        return kind + '\u0000' + (scope == null ? "" : scope) + '\u0000' + (target == null ? "" : target);
    }

    /** 色号 → 颜色名（1..6 → 红..紫），越界返回空串。 */
    public static String name(int color) {
        return color >= 1 && color <= NAMES.length ? NAMES[color - 1] : "";
    }

    /**
     * 参数标记的键：<b>位置 + 名字</b>，故意不带域名。
     * <p>
     * 参数表是跨接口 / 跨域名的聚合视图，同一个 {@code page} 在不同域名下也是"同一个参数"；
     * 带上域名会让同一行在不同视图里颜色对不上。UI 和自测都用这个方法拼，别各拼各的。
     */
    public static String paramTarget(String where, String name) {
        return (where == null ? "" : where) + '\u0000' + (name == null ? "" : name);
    }

    /** 排序模式：默认（只把有色的顶上来）、按色号升、按色号降。 */
    public static final int SORT_DEFAULT = 0;
    public static final int SORT_ASC = 1;
    public static final int SORT_DESC = 2;

    /**
     * 两个色号谁排前面（排序规则只有这一处，UI 和自测都走它）。
     * <p>
     * 默认模式只分「有色 / 无色」两组，返回 0 让调用方的稳定排序保留原来的行序；
     * 另两个模式按色号排，<b>无色永远垫底</b>——「有色置顶」在任何模式下都成立。
     */
    public static int compare(int a, int b, int mode) {
        if (mode == SORT_DEFAULT) {
            boolean ca = a > 0;
            boolean cb = b > 0;
            return ca == cb ? 0 : (ca ? -1 : 1);
        }
        int ra = a <= 0 ? 100 : (mode == SORT_DESC ? 100 - a : a);
        int rb = b <= 0 ? 100 : (mode == SORT_DESC ? 100 - b : b);
        return Integer.compare(ra, rb);
    }

    /** 色号 → 颜色名反查（"红" → 1），认不出返回 0。 */
    public static int indexOf(String colorName) {
        if (colorName == null) {
            return 0;
        }
        String s = colorName.trim();
        for (int i = 0; i < NAMES.length; i++) {
            if (NAMES[i].equals(s)) {
                return i + 1;
            }
        }
        return 0;
    }

    /** 菜单里的色块（纯色 + 一圈描边，浅色也能看出边界）。 */
    public static javax.swing.Icon swatch(int color) {
        final Color c = color >= 1 && color <= RGB.length ? new Color(RGB[color - 1]) : Color.WHITE;
        return new javax.swing.Icon() {
            @Override
            public void paintIcon(java.awt.Component comp, java.awt.Graphics g, int x, int y) {
                java.awt.Graphics2D g2 = (java.awt.Graphics2D) g.create();
                try {
                    g2.setRenderingHint(java.awt.RenderingHints.KEY_ANTIALIASING,
                            java.awt.RenderingHints.VALUE_ANTIALIAS_ON);
                    g2.setColor(c);
                    g2.fillRoundRect(x, y, getIconWidth(), getIconHeight(), 4, 4);
                    g2.setColor(new Color(0, 0, 0, 60));
                    g2.drawRoundRect(x, y, getIconWidth() - 1, getIconHeight() - 1, 4, 4);
                } finally {
                    g2.dispose();
                }
            }

            @Override
            public int getIconWidth() {
                return 12;
            }

            @Override
            public int getIconHeight() {
                return 12;
            }
        };
    }

    /**
     * 行底色：纯色掺一点点到表格自己的底色上，而不是固定写死淡色。
     * <p>
     * 这样 Burp 换浅色 / 深色主题时，文字和底色的对比度都还成立——
     * 直接 {@code new Color(0xFFEBEE)} 那种写法在深色主题下会把白字压成看不见。
     */
    public static Color tint(int color, Color background) {
        if (color < 1 || color > RGB.length) {
            return background;
        }
        Color base = new Color(RGB[color - 1]);
        Color bg = background == null ? Color.WHITE : background;
        return new Color(
                (int) Math.round(base.getRed() * TINT + bg.getRed() * (1 - TINT)),
                (int) Math.round(base.getGreen() * TINT + bg.getGreen() * (1 - TINT)),
                (int) Math.round(base.getBlue() * TINT + bg.getBlue() * (1 - TINT)));
    }
}
