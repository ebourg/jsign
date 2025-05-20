/*
 * Copyright 2025 Emmanuel Bourg
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

/**
 * Configuration for a SunPKCS11 provider.
 *
 * @since 7.2
 */
class PKCS11Configuration {

    private String name;
    private File library;
    private long slot = -1;

    PKCS11Configuration name(String name) {
        this.name = name;
        return this;
    }

    PKCS11Configuration library(File library) {
        this.library = library;
        return this;
    }

    PKCS11Configuration slot(long slot) {
        this.slot = slot;
        return this;
    }

    public String toString() {
        String configuration = "--name=" + name + "\n";
        configuration += "library = \"" + library.getAbsolutePath().replace("\\", "\\\\") + "\"\n";
        if (slot >= 0) {
            configuration += "slot=" + slot;
        }
        return configuration;
    }
}
