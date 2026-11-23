package yuc;

import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * 路径 / 参数两个搜索框共用的「单条件」匹配引擎。
 * <p>
 * 只管一件事：{@code hay} 里有没有 {@code q}，支持忽略大小写与正则。
 * 复杂的「列 + 关系 + 值」组合走 {@link SearchRule}——那是下拉选出来的，
 * 用户不用背列名、不用数括号。
 */
public final class TextFilter {

    private TextFilter() {
    }

    /** 单条件：hay 里有没有 q。正则写错不抛异常，只是这条不匹配（搜索框是边打字边编译的）。 */
    public static boolean contains(String hay, String q, boolean ignoreCase, boolean regex) {
        String h = hay == null ? "" : hay;
        if (q == null || q.isEmpty()) {
            return true;
        }
        if (!regex) {
            return ignoreCase ? h.toLowerCase().contains(q.toLowerCase()) : h.contains(q);
        }
        try {
            int flags = ignoreCase ? Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE : 0;
            return Pattern.compile(q, flags).matcher(h).find();
        } catch (PatternSyntaxException e) {
            return false;
        }
    }
}
