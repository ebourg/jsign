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

package net.jsign.spi;

import java.io.File;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * {@link SignableProvider} for files matching a specific extension.
 *
 * @since 7.0
 */
public abstract class ExtensionBasedSignableProvider implements SignableProvider {

    private final Set<String> extensions;

    public ExtensionBasedSignableProvider(String... extensions) {
        this.extensions = new HashSet<>(Arrays.asList(extensions));
    }

    @Override
    public boolean isSupported(File file) {
        String extension = file.getName().substring(file.getName().lastIndexOf('.') + 1);
        return extensions.contains(extension.toLowerCase());
    }
}
