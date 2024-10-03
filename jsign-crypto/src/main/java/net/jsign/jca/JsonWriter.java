/**
 * Copyright 2024 Emmanuel Bourg
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.jsign.jca;

import java.util.Collection;
import java.util.Iterator;
import java.util.Map;
import java.util.stream.Stream;

/**
 * Simple JSON formatter.
 *
 * @since 7.0
 */
class JsonWriter {

    public static String format(Object object) {
        StringBuilder out = new StringBuilder();
        format(object, out);
        return out.toString();
    }

    public static void format(Object value, StringBuilder out) {
        if (value instanceof String) {
            String s = (String) value;
            out.append("\"");
            out.append(s.replace("\\", "\\\\").replace("\"", "\\\""));
            out.append("\"");

        } else if (value instanceof Number || value instanceof Boolean) {
            out.append(value);

        } else if (value instanceof Map) {
            Map map = (Map) value;
            out.append("{");
            Iterator<Map.Entry> iterator = map.entrySet().iterator();
            while (iterator.hasNext()) {
                Map.Entry entry = iterator.next();
                format(entry.getKey(), out);
                out.append(":");
                format(entry.getValue(), out);
                if (iterator.hasNext()) {
                    out.append(',');
                }
            }
            out.append("}");

        } else if (value instanceof Collection) {
            Collection collection = (Collection) value;
            out.append("[");
            Iterator<?> iterator = collection.iterator();
            while (iterator.hasNext()) {
                format(iterator.next(), out);
                if (iterator.hasNext()) {
                    out.append(',');
                }
            }
            out.append("]");

        } else if (value instanceof Object[]) {
            Object[] array = (Object[]) value;
            out.append("[");
            Iterator<?> iterator = Stream.of(array).iterator();
            while (iterator.hasNext()) {
                format(iterator.next(), out);
                if (iterator.hasNext()) {
                    out.append(',');
                }
            }
            out.append("]");

        } else if (value == null) {
            out.append("null");

        } else {
            throw new RuntimeException("Unsupported type: " + value.getClass().getSimpleName());
        }
    }
}
