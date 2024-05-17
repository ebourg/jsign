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

package net.jsign;

import java.io.File;
import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.FileVisitor;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.List;
import java.util.StringTokenizer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Scans a directory recursively and returns the files matching a pattern.
 *
 * @since 6.1
 */
class DirectoryScanner {

    /**
     * Scans the current directory for files matching the specified pattern.
     *
     * @param glob the glob pattern ({@code foo/**}{@code /*bar/*.exe})
     */
    public List<Path> scan(String glob) throws IOException {
        // normalize the pattern
        glob = glob.replace('\\', '/').replace("/+", "/");

        // adjust the base directory
        String basedir = findBaseDirectory(glob);

        // strip the base directory from the pattern
        glob = glob.substring(basedir.length());
        Pattern pattern = Pattern.compile(globToRegExp(glob));

        int maxDepth = maxPatternDepth(glob);

        // let's scan the files
        List<Path> matches = new ArrayList<>();
        Files.walkFileTree(new File(basedir).toPath(), new FileVisitor<Path>() {
            private int depth = -1;

            @Override
            public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) {
                String name = dir.getFileName().toString();
                if (depth + 1 > maxDepth || ".svn".equals(name) || ".git".equals(name)) {
                    return FileVisitResult.SKIP_SUBTREE;
                } else {
                    depth++;
                    return FileVisitResult.CONTINUE;
                }
            }

            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                String filename = file.toString();
                filename = filename.replaceAll("\\\\", "/");
                if (filename.startsWith("./")) {
                    filename = filename.substring(2);
                }
                if (filename.startsWith(basedir)) {
                    filename = filename.substring(basedir.length());
                }
                if (pattern.matcher(filename).matches()) {
                    matches.add(file);
                }

                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult visitFileFailed(Path file, IOException exc) {
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult postVisitDirectory(Path dir, IOException exc) {
                depth--;
                return FileVisitResult.CONTINUE;
            }
        });

        return matches;
    }

    /**
     * Converts a glob pattern into a regular expression.
     *
     * @param glob the glob pattern to convert ({@code foo/**}{@code /bar/*.exe})
     */
    String globToRegExp(String glob) {
        String delimiters = "/\\";
        StringTokenizer tokenizer = new StringTokenizer(glob, delimiters, true);

        boolean ignoreNextSeparator = false;
        StringBuilder pattern = new StringBuilder();
        while (tokenizer.hasMoreTokens()) {
            String token = tokenizer.nextToken();
            if (token.length() == 1 && delimiters.contains(token)) {
                if (!ignoreNextSeparator) {
                    pattern.append("/");
                }
            } else if ("**".equals(token)){
                pattern.append("(?:|.*/)");
                ignoreNextSeparator = true;
            } else if (token.contains("*")) {
                ignoreNextSeparator = false;
                pattern.append("\\Q" + token.replaceAll("\\*", "\\\\E[^/]*\\\\Q") + "\\E");
            } else {
                ignoreNextSeparator = false;
                pattern.append("\\Q").append(token).append("\\E");
            }
        }

        return pattern.toString().replaceAll("/+", "/");
    }

    /**
     * Finds the base directory of the specified pattern.
     */
    String findBaseDirectory(String pattern) {
        Pattern regexp = Pattern.compile("([^*]*/).*");
        Matcher matcher = regexp.matcher(pattern);
        if (matcher.matches()) {
            return matcher.group(1);
        } else {
            return "";
        }
    }

    /**
     * Returns the maximum depth of the pattern (stripped from its base directory).
     */
    int maxPatternDepth(String pattern) {
        if (pattern.contains("**")) {
            return 50;
        }

        int depth = 0;
        for (int i = 0; i < pattern.length(); i++) {
            if (pattern.charAt(i) == '/') {
                depth++;
            }
        }

        return depth;
    }
}
