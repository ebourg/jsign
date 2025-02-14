/*
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
import java.nio.file.FileSystems;

/**
 * Helper class to retrieve information about the operating system.
 *
 * @since 7.0
 */
class OSUtils {

    /**
     * Returns the cache directory for the specified application.
     *
     * @param application the name of the application
     */
    public static File getCacheDirectory(String application) {
        File directory;
        String osname = System.getProperty("os.name");
        if (System.getProperty("jsign.cachedir") != null) {
            directory = new File(System.getProperty("jsign.cachedir"));
        } else if (osname.startsWith("Windows")) {
            directory = FileSystems.getDefault().getPath(System.getenv("LOCALAPPDATA"), "cache", application).toFile();
        } else if (osname.contains("Mac OS X")) {
            directory = FileSystems.getDefault().getPath(System.getProperty("user.home"), "Library", "Caches", application).toFile();
        } else if (System.getenv("XDG_CACHE_HOME") != null) {
            directory = FileSystems.getDefault().getPath(System.getenv("XDG_CACHE_HOME"), application.toLowerCase()).toFile();
        } else {
            directory = FileSystems.getDefault().getPath(System.getProperty("user.home"), ".cache", application.toLowerCase()).toFile();
        }

        directory.mkdirs();
        if (!directory.isDirectory() || !directory.canWrite()) {
            // fallback to the current directory
            directory = FileSystems.getDefault().getPath(".cache", application.toLowerCase()).toFile();
            directory.mkdirs();
        }

        return directory;
    }
}
