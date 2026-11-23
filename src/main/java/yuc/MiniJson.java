package yuc;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 极简 JSON 解析 / 序列化。
 * <p>
 * 存在的理由：插件要「不依赖任何第三方库」就能跑。Burp 自带 gson，但版本随 Burp 变，
 * 打到自己 jar 里又要考虑类加载顺序，不如写 200 行自己解析——反正只处理 JSON。
 * <p>
 * 解析产物：LinkedHashMap &lt;String,Object&gt; / ArrayList&lt;Object&gt; / String /
 * Long（放得下的整数）/ BigInteger（放不下的整数，避免 19 位 ID 被截断）/ Double / Boolean / null。
 */
public final class MiniJson {

    private MiniJson() {
    }

    // ---------------------------------------------------------------- 解析

    public static Object parse(String text) {
        if (text == null) {
            return null;
        }
        Parser p = new Parser(text);
        p.skipWs();
        Object v = p.readValue();
        p.skipWs();
        if (!p.eof()) {
            throw new IllegalArgumentException("JSON 尾部还有多余内容 @" + p.i);
        }
        return v;
    }

    /** 解析失败返回 null，不抛异常（抓包数据不可信）。 */
    public static Object tryParse(String text) {
        try {
            return parse(text);
        } catch (RuntimeException e) {
            return null;
        }
    }

    private static final class Parser {
        private final String s;
        private int i;

        Parser(String s) {
            this.s = s;
        }

        boolean eof() {
            return i >= s.length();
        }

        void skipWs() {
            while (i < s.length() && Character.isWhitespace(s.charAt(i))) {
                i++;
            }
        }

        Object readValue() {
            skipWs();
            if (eof()) {
                throw new IllegalArgumentException("JSON 意外结束");
            }
            char c = s.charAt(i);
            switch (c) {
                case '{':
                    return readObject();
                case '[':
                    return readArray();
                case '"':
                    return readString();
                case 't':
                    expect("true");
                    return Boolean.TRUE;
                case 'f':
                    expect("false");
                    return Boolean.FALSE;
                case 'n':
                    expect("null");
                    return null;
                default:
                    return readNumber();
            }
        }

        void expect(String word) {
            if (!s.startsWith(word, i)) {
                throw new IllegalArgumentException("JSON 期望 " + word + " @" + i);
            }
            i += word.length();
        }

        Map<String, Object> readObject() {
            Map<String, Object> map = new LinkedHashMap<>();
            i++; // {
            skipWs();
            if (!eof() && s.charAt(i) == '}') {
                i++;
                return map;
            }
            while (true) {
                skipWs();
                if (eof() || s.charAt(i) != '"') {
                    throw new IllegalArgumentException("JSON 对象的键必须是字符串 @" + i);
                }
                String key = readString();
                skipWs();
                if (eof() || s.charAt(i) != ':') {
                    throw new IllegalArgumentException("JSON 缺少冒号 @" + i);
                }
                i++;
                map.put(key, readValue());
                skipWs();
                if (eof()) {
                    throw new IllegalArgumentException("JSON 对象未闭合");
                }
                char c = s.charAt(i++);
                if (c == '}') {
                    return map;
                }
                if (c != ',') {
                    throw new IllegalArgumentException("JSON 对象里期望 , 或 } @" + (i - 1));
                }
            }
        }

        List<Object> readArray() {
            List<Object> list = new ArrayList<>();
            i++; // [
            skipWs();
            if (!eof() && s.charAt(i) == ']') {
                i++;
                return list;
            }
            while (true) {
                list.add(readValue());
                skipWs();
                if (eof()) {
                    throw new IllegalArgumentException("JSON 数组未闭合");
                }
                char c = s.charAt(i++);
                if (c == ']') {
                    return list;
                }
                if (c != ',') {
                    throw new IllegalArgumentException("JSON 数组里期望 , 或 ] @" + (i - 1));
                }
            }
        }

        String readString() {
            i++; // "
            StringBuilder sb = new StringBuilder();
            while (true) {
                if (eof()) {
                    throw new IllegalArgumentException("JSON 字符串未闭合");
                }
                char c = s.charAt(i++);
                if (c == '"') {
                    return sb.toString();
                }
                if (c != '\\') {
                    sb.append(c);
                    continue;
                }
                if (eof()) {
                    throw new IllegalArgumentException("JSON 转义未完成");
                }
                char e = s.charAt(i++);
                switch (e) {
                    case '"': sb.append('"'); break;
                    case '\\': sb.append('\\'); break;
                    case '/': sb.append('/'); break;
                    case 'b': sb.append('\b'); break;
                    case 'f': sb.append('\f'); break;
                    case 'n': sb.append('\n'); break;
                    case 'r': sb.append('\r'); break;
                    case 't': sb.append('\t'); break;
                    case 'u':
                        if (i + 4 > s.length()) {
                            throw new IllegalArgumentException("JSON \\u 转义不完整");
                        }
                        sb.append((char) Integer.parseInt(s.substring(i, i + 4), 16));
                        i += 4;
                        break;
                    default:
                        throw new IllegalArgumentException("JSON 未知转义 \\" + e);
                }
            }
        }

        Object readNumber() {
            int start = i;
            boolean fractional = false;
            while (i < s.length()) {
                char c = s.charAt(i);
                if (c == '-' || c == '+' || (c >= '0' && c <= '9')) {
                    i++;
                } else if (c == '.' || c == 'e' || c == 'E') {
                    fractional = true;
                    i++;
                } else {
                    break;
                }
            }
            String raw = s.substring(start, i);
            if (raw.isEmpty()) {
                throw new IllegalArgumentException("JSON 非法字符 @" + start);
            }
            if (fractional) {
                return Double.valueOf(raw);
            }
            try {
                return Long.valueOf(raw);
            } catch (NumberFormatException tooBig) {
                return new BigInteger(raw);
            }
        }
    }

    // ---------------------------------------------------------------- 序列化

    /** 紧凑输出（单行），用于日志。 */
    public static String write(Object value) {
        StringBuilder sb = new StringBuilder();
        writeValue(sb, value, false, 0);
        return sb.toString();
    }

    /** 2 空格缩进，用于落盘（人能看懂、diff 干净）。 */
    public static String pretty(Object value) {
        StringBuilder sb = new StringBuilder();
        writeValue(sb, value, true, 0);
        sb.append('\n');
        return sb.toString();
    }

    private static void writeValue(StringBuilder sb, Object v, boolean pretty, int depth) {
        if (v == null) {
            sb.append("null");
        } else if (v instanceof String) {
            writeString(sb, (String) v);
        } else if (v instanceof Boolean) {
            sb.append(v.toString());
        } else if (v instanceof BigInteger) {
            sb.append(v.toString());
        } else if (v instanceof Double || v instanceof Float) {
            double d = ((Number) v).doubleValue();
            if (d == Math.rint(d) && !Double.isInfinite(d) && Math.abs(d) < 1e15) {
                sb.append((long) d);
            } else {
                sb.append(d);
            }
        } else if (v instanceof Number) {
            sb.append(v.toString());
        } else if (v instanceof Map) {
            writeObject(sb, (Map<?, ?>) v, pretty, depth);
        } else if (v instanceof Iterable) {
            writeArray(sb, (Iterable<?>) v, pretty, depth);
        } else {
            writeString(sb, String.valueOf(v));
        }
    }

    private static void writeObject(StringBuilder sb, Map<?, ?> map, boolean pretty, int depth) {
        if (map.isEmpty()) {
            sb.append("{}");
            return;
        }
        sb.append('{');
        boolean first = true;
        for (Map.Entry<?, ?> e : map.entrySet()) {
            if (!first) {
                sb.append(',');
            }
            first = false;
            if (pretty) {
                newline(sb, depth + 1);
            }
            writeString(sb, String.valueOf(e.getKey()));
            sb.append(pretty ? ": " : ":");
            writeValue(sb, e.getValue(), pretty, depth + 1);
        }
        if (pretty) {
            newline(sb, depth);
        }
        sb.append('}');
    }

    private static void writeArray(StringBuilder sb, Iterable<?> it, boolean pretty, int depth) {
        boolean empty = true;
        StringBuilder inner = new StringBuilder();
        for (Object o : it) {
            if (!empty) {
                inner.append(',');
            }
            empty = false;
            if (pretty) {
                newline(inner, depth + 1);
            }
            writeValue(inner, o, pretty, depth + 1);
        }
        if (empty) {
            sb.append("[]");
            return;
        }
        sb.append('[').append(inner);
        if (pretty) {
            newline(sb, depth);
        }
        sb.append(']');
    }

    private static void newline(StringBuilder sb, int depth) {
        sb.append('\n');
        for (int k = 0; k < depth; k++) {
            sb.append("  ");
        }
    }

    private static void writeString(StringBuilder sb, String s) {
        sb.append('"');
        for (int k = 0; k < s.length(); k++) {
            char c = s.charAt(k);
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                case '\b': sb.append("\\b"); break;
                case '\f': sb.append("\\f"); break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        sb.append('"');
    }
}
