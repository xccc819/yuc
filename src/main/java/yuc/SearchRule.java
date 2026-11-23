package yuc;

import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * 高级搜索的一条条件：<b>列 + 关系 + 值</b>，以及它和前一条是「且」还是「或」。
 * <p>
 * 为什么不用文本表达式（{@code a and (b or c)}）：列名要用户背、括号要用户数，
 * 而且「状态 大于 400」这种根本没法用纯文本表达。改成下拉选列 + 下拉选关系，
 * 关系的可选项跟着列走（文本列给「包含/开头是/正则」，数字列再多给「大于/小于」）。
 * <p>
 * 求值规则：**「且」优先于「或」**，和 SQL 一样。所以
 * {@code A 且 B 或 C} = {@code (A and B) or C}。
 */
public final class SearchRule {

    /** 比较关系。 */
    public enum Op {
        CONTAINS("包含"),
        NOT_CONTAINS("不包含"),
        EQUALS("等于"),
        NOT_EQUALS("不等于"),
        STARTS("开头是"),
        ENDS("结尾是"),
        REGEX("正则匹配"),
        NOT_REGEX("正则不匹配"),
        GT("大于"),
        GE("大于等于"),
        LT("小于"),
        LE("小于等于");

        public final String label;

        Op(String label) {
            this.label = label;
        }

        /** 只能用在数字列（状态、响应字节、参数个数、接口数）上。 */
        public boolean numeric() {
            return this == GT || this == GE || this == LT || this == LE;
        }

        @Override
        public String toString() {
            return label;
        }
    }

    /**
     * 可选的列。{@code numeric} 为真的列会多出「大于/小于」那四个关系；
     * {@code options} 非空表示值只能从这几项里挑（下拉选，别让人手打「红」还是「红色」）。
     */
    public static final class Field {
        public final String key;
        public final String label;
        public final boolean numeric;
        /** 可选的取值；null = 自由填写。 */
        public final String[] options;

        Field(String key, String label, boolean numeric) {
            this(key, label, numeric, null);
        }

        Field(String key, String label, boolean numeric, String[] options) {
            this.key = key;
            this.label = label;
            this.numeric = numeric;
            this.options = options;
        }

        @Override
        public String toString() {
            return label;
        }
    }

    private static Field f(String key, String label, boolean numeric) {
        return new Field(key, label, numeric);
    }

    /** 路径表能筛的列。 */
    public static final Field[] PATH_FIELDS = {
            f("path", "路径", false),
            f("method", "方法", false),
            f("url", "完整 URL", false),
            f("status", "状态码", true),
            f("bytes", "响应字节", true),
            f("params", "参数个数", true),
            f("tool", "来源", false),
            // 颜色是右键标上去的，表里没有这一列，只能在这儿用
            new Field("color", "颜色", false, Marks.NAMES),
    };

    /** 参数表能筛的列。 */
    public static final Field[] PARAM_FIELDS = {
            f("name", "参数名", false),
            f("full", "完整路径", false),
            f("where", "位置", false),
            f("example", "示例值", false),
            f("endpoints", "接口数", true),
            new Field("color", "颜色", false, Marks.NAMES),
    };

    public final String field;
    public final Op op;
    public final String value;
    /** true = 与上一条是「或」；false = 「且」。第一条忽略。 */
    public final boolean or;

    public SearchRule(String field, Op op, String value, boolean or) {
        this.field = field;
        this.op = op == null ? Op.CONTAINS : op;
        this.value = value == null ? "" : value;
        this.or = or;
    }

    /** 这一条在说明文字里长什么样（给按钮的 tooltip 用）。 */
    public String describe() {
        return label(field) + " " + op.label + " " + value;
    }

    /** 拿一个单元格的值来试这一条。 */
    public boolean matches(String cell, boolean ignoreCase) {
        return test(cell, op, value, ignoreCase);
    }

    public static String label(String fieldKey) {
        for (Field fd : PATH_FIELDS) {
            if (fd.key.equals(fieldKey)) {
                return fd.label;
            }
        }
        for (Field fd : PARAM_FIELDS) {
            if (fd.key.equals(fieldKey)) {
                return fd.label;
            }
        }
        return fieldKey;
    }

    /** 拼成一行的说明：{@code 路径 包含 /user 且 状态码 大于 400 或 来源 等于 Repeater}。 */
    public static String describe(List<SearchRule> rules) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < rules.size(); i++) {
            if (i > 0) {
                sb.append(rules.get(i).or ? " 或 " : " 且 ");
            }
            sb.append(rules.get(i).describe());
        }
        return sb.toString();
    }

    /** 把条件套到一行数据上。空条件返回 true（等于没筛）。 */
    public static boolean match(List<SearchRule> rules, Map<String, String> row, boolean ignoreCase) {
        if (rules == null || rules.isEmpty()) {
            return true;
        }
        boolean any = false;
        boolean group = true;
        for (int i = 0; i < rules.size(); i++) {
            SearchRule r = rules.get(i);
            boolean ok = test(row.get(r.field), r.op, r.value, ignoreCase);
            if (i == 0) {
                group = ok;
            } else if (r.or) {
                any = any || group;
                group = ok;
            } else {
                group = group && ok;
            }
        }
        return any || group;
    }

    /** 单元格 → 一条关系的判定。 */
    public static boolean test(String cell, Op op, String arg, boolean ignoreCase) {
        String v = cell == null ? "" : cell;
        String a = arg == null ? "" : arg;
        if (op == null || a.isEmpty()) {
            return true; // 没填值的条件等于没写
        }
        switch (op) {
            case CONTAINS:
                return icContains(v, a, ignoreCase);
            case NOT_CONTAINS:
                return !icContains(v, a, ignoreCase);
            case EQUALS:
                return ignoreCase ? v.equalsIgnoreCase(a) : v.equals(a);
            case NOT_EQUALS:
                return ignoreCase ? !v.equalsIgnoreCase(a) : !v.equals(a);
            case STARTS:
                return startsWith(v, a, ignoreCase);
            case ENDS:
                return endsWith(v, a, ignoreCase);
            case REGEX:
                return regex(v, a, ignoreCase);
            case NOT_REGEX:
                return !regex(v, a, ignoreCase);
            default:
                return compare(v, a, op);
        }
    }

    private static boolean icContains(String v, String a, boolean ic) {
        return ic ? v.toLowerCase().contains(a.toLowerCase()) : v.contains(a);
    }

    private static boolean startsWith(String v, String a, boolean ic) {
        return ic ? v.toLowerCase().startsWith(a.toLowerCase()) : v.startsWith(a);
    }

    private static boolean endsWith(String v, String a, boolean ic) {
        return ic ? v.toLowerCase().endsWith(a.toLowerCase()) : v.endsWith(a);
    }

    private static boolean regex(String v, String a, boolean ic) {
        try {
            int flags = ic ? Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE : 0;
            return Pattern.compile(a, flags).matcher(v).find();
        } catch (PatternSyntaxException e) {
            return false; // 正则写错不弹窗，只是这条不匹配
        }
    }

    /** 数字比较：两边都得是数字，否则不成立（别拿 "" 当 0）。 */
    private static boolean compare(String v, String a, Op op) {
        Double left = num(v);
        Double right = num(a);
        if (left == null || right == null) {
            return false;
        }
        switch (op) {
            case GT:
                return left > right;
            case GE:
                return left >= right;
            case LT:
                return left < right;
            case LE:
                return left <= right;
            default:
                return false;
        }
    }

    private static Double num(String s) {
        if (s == null || s.trim().isEmpty()) {
            return null;
        }
        try {
            return Double.valueOf(s.trim());
        } catch (NumberFormatException e) {
            return null;
        }
    }
}
