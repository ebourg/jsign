/*
 * Copyright 2026 Emmanuel Bourg
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

package net.jsign;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Utility class to process text containing custom pseudo-XML tags for terminal styling.
 *
 * <p>Supported tags include text formatting (e.g., {@code <b>}, {@code <i>}) and standard text
 * colors (e.g., {@code <red>}, {@code <green>}, etc.).</p>
 *
 * <p>Tags are either translated into standard ANSI escape sequences for compatible terminals, or stripped
 * out entirely (useful for raw text logs or unsupported terminals). Unknown tags are left unchanged.</p>
 *
 * @since 7.5
 */
class AnsiFormatter {

    private static final Pattern TAG_PATTERN = Pattern.compile("<(/)?(b|i|u|red|green|yellow|blue|magenta|cyan|white|gray)>");

    private static final Map<String, String> REPLACEMENTS = new HashMap<>();
    static {
        REPLACEMENTS.put("b",       "\033[1m");
        REPLACEMENTS.put("i",       "\033[3m");
        REPLACEMENTS.put("u",       "\033[4m");
        REPLACEMENTS.put("red",     "\033[31m");
        REPLACEMENTS.put("green",   "\033[32m");
        REPLACEMENTS.put("yellow",  "\033[33m");
        REPLACEMENTS.put("blue",    "\033[34m");
        REPLACEMENTS.put("magenta", "\033[35m");
        REPLACEMENTS.put("cyan",    "\033[36m");
        REPLACEMENTS.put("white",   "\033[37m");
        REPLACEMENTS.put("gray",    "\033[90m");
    }

    private static final String RESET = "\033[0m";

    private final boolean ansiEnabled;

    /**
     * Creates a new ANSI formatter. ANSI support is automatically detected.
     */
    public AnsiFormatter() {
        this.ansiEnabled = isAnsiSupported();
    }

    /**
     * Creates a new ANSI formatter with the specified ANSI support.
     *
     * @param ansiEnabled {@code true} to convert tags to ANSI escape sequences;
     *                    {@code false} to clean and remove the markup tags entirely
     */
    public AnsiFormatter(boolean ansiEnabled) {
        this.ansiEnabled = ansiEnabled;
    }

    /**
     * Processes the input text according to the terminal's ANSI capability.
     *
     * @param text       the input string containing custom markup tags
     * @return the processed string, or {@code null} if the input was null
     */
    public String format(String text) {
        if (text == null || !text.contains("<")) {
            return text;
        }

        Matcher matcher = TAG_PATTERN.matcher(text);
        StringBuffer buf = new StringBuffer();

        while (matcher.find()) {
            String replacement;

            if (ansiEnabled) {
                boolean closing = matcher.group(1) != null;
                String tagName = matcher.group(2);
                replacement = closing ? RESET : REPLACEMENTS.get(tagName);
            } else {
                replacement = "";
            }

            matcher.appendReplacement(buf, replacement);
        }
        matcher.appendTail(buf);

        return buf.toString();
    }

    /**
     * Checks if the current terminal supports ANSI escape sequences.
     */
    public static boolean isAnsiSupported() {
        if (System.console() == null) {
            return false;
        }

        if (System.getProperty("os.name").toLowerCase().contains("win")) {
            if (System.getenv("WT_SESSION") != null) {
                return true;
            }

            Integer windowsVersion = getWindowsVersion();
            if (windowsVersion == null || windowsVersion < 10) {
                return false;
            }

            try {
                // "cmd.exe /c" triggers a call to SetConsoleMode and enables ANSI codes on the old Windows terminal (Windows 10+ only)
                new ProcessBuilder("cmd.exe", "/c").inheritIO().start().waitFor(150, TimeUnit.MILLISECONDS);
            } catch (Exception e) {
                return false;
            }
        }

        return true;
    }

    /**
     * Returns the version of Windows.
     */
    private static Integer getWindowsVersion() {
        String version = System.getProperty("os.version");
        Pattern pattern = Pattern.compile("(\\d+)\\.(\\d+)");
        Matcher matcher = pattern.matcher(version);
        if (matcher.find()) {
            return Integer.parseInt(matcher.group(1));
        }
        return null;
    }
}
