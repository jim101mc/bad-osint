package com.osintcorrelator.json;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class Json {
    private Json() {
    }

    public static Object parse(String input) {
        return new Parser(input).parse();
    }

    public static String stringify(Object value) {
        StringBuilder builder = new StringBuilder();
        write(builder, value);
        return builder.toString();
    }

    public static Map<String, Object> expectObject(Object value) {
        if (value instanceof Map<?, ?> map) {
            Map<String, Object> typed = new LinkedHashMap<>();
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                typed.put(String.valueOf(entry.getKey()), entry.getValue());
            }
            return typed;
        }
        throw new IllegalArgumentException("expected JSON object");
    }

    public static List<Object> array(Map<String, Object> object, String key) {
        Object value = object.get(key);
        if (value instanceof List<?> list) {
            return new ArrayList<>(list);
        }
        return List.of();
    }

    public static String string(Map<String, Object> object, String key) {
        String value = string(object, key, null);
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(key + " is required");
        }
        return value;
    }

    public static String string(Map<String, Object> object, String key, String fallback) {
        Object value = object.get(key);
        return value == null ? fallback : String.valueOf(value);
    }

    public static double decimal(Map<String, Object> object, String key, double fallback) {
        Object value = object.get(key);
        if (value instanceof Number number) {
            return number.doubleValue();
        }
        if (value instanceof String text && !text.isBlank()) {
            return Double.parseDouble(text);
        }
        return fallback;
    }

    @SuppressWarnings("unchecked")
    private static void write(StringBuilder builder, Object value) {
        if (value == null) {
            builder.append("null");
        } else if (value instanceof String text) {
            builder.append('"').append(escape(text)).append('"');
        } else if (value instanceof Number || value instanceof Boolean) {
            builder.append(value);
        } else if (value instanceof Map<?, ?> map) {
            builder.append('{');
            boolean first = true;
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                if (!first) {
                    builder.append(',');
                }
                first = false;
                write(builder, String.valueOf(entry.getKey()));
                builder.append(':');
                write(builder, entry.getValue());
            }
            builder.append('}');
        } else if (value instanceof Iterable<?> iterable) {
            builder.append('[');
            boolean first = true;
            for (Object item : iterable) {
                if (!first) {
                    builder.append(',');
                }
                first = false;
                write(builder, item);
            }
            builder.append(']');
        } else {
            write(builder, String.valueOf(value));
        }
    }

    private static String escape(String value) {
        return value
                .replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\b", "\\b")
                .replace("\f", "\\f")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    private static final class Parser {
        private final String input;
        private int index;

        private Parser(String input) {
            this.input = input == null ? "" : input;
        }

        private Object parse() {
            Object value = value();
            whitespace();
            if (index != input.length()) {
                throw new IllegalArgumentException("invalid JSON");
            }
            return value;
        }

        private Object value() {
            whitespace();
            if (index >= input.length()) {
                throw new IllegalArgumentException("empty JSON");
            }
            char current = input.charAt(index);
            if (current == '{') return object();
            if (current == '[') return array();
            if (current == '"') return string();
            if (current == 't' || current == 'f') return bool();
            if (current == 'n') return nil();
            return number();
        }

        private Map<String, Object> object() {
            expect('{');
            Map<String, Object> map = new LinkedHashMap<>();
            whitespace();
            if (peek('}')) {
                index++;
                return map;
            }
            while (true) {
                String key = string();
                whitespace();
                expect(':');
                map.put(key, value());
                whitespace();
                if (peek('}')) {
                    index++;
                    return map;
                }
                expect(',');
            }
        }

        private List<Object> array() {
            expect('[');
            List<Object> list = new ArrayList<>();
            whitespace();
            if (peek(']')) {
                index++;
                return list;
            }
            while (true) {
                list.add(value());
                whitespace();
                if (peek(']')) {
                    index++;
                    return list;
                }
                expect(',');
            }
        }

        private String string() {
            expect('"');
            StringBuilder builder = new StringBuilder();
            while (index < input.length()) {
                char current = input.charAt(index++);
                if (current == '"') {
                    return builder.toString();
                }
                if (current == '\\') {
                    if (index >= input.length()) {
                        throw new IllegalArgumentException("invalid escape");
                    }
                    char escaped = input.charAt(index++);
                    builder.append(switch (escaped) {
                        case '"', '\\', '/' -> escaped;
                        case 'b' -> '\b';
                        case 'f' -> '\f';
                        case 'n' -> '\n';
                        case 'r' -> '\r';
                        case 't' -> '\t';
                        default -> throw new IllegalArgumentException("unsupported escape");
                    });
                } else {
                    builder.append(current);
                }
            }
            throw new IllegalArgumentException("unterminated string");
        }

        private Boolean bool() {
            if (input.startsWith("true", index)) {
                index += 4;
                return true;
            }
            if (input.startsWith("false", index)) {
                index += 5;
                return false;
            }
            throw new IllegalArgumentException("invalid boolean");
        }

        private Object nil() {
            if (input.startsWith("null", index)) {
                index += 4;
                return null;
            }
            throw new IllegalArgumentException("invalid null");
        }

        private Number number() {
            int start = index;
            while (index < input.length() && "-+0123456789.eE".indexOf(input.charAt(index)) >= 0) {
                index++;
            }
            if (start == index) {
                throw new IllegalArgumentException("invalid JSON value");
            }
            String value = input.substring(start, index);
            return value.contains(".") || value.contains("e") || value.contains("E")
                    ? Double.parseDouble(value)
                    : Long.parseLong(value);
        }

        private void whitespace() {
            while (index < input.length() && Character.isWhitespace(input.charAt(index))) {
                index++;
            }
        }

        private boolean peek(char expected) {
            return index < input.length() && input.charAt(index) == expected;
        }

        private void expect(char expected) {
            whitespace();
            if (!peek(expected)) {
                throw new IllegalArgumentException("expected '" + expected + "'");
            }
            index++;
        }
    }
}
