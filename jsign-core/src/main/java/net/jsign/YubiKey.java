/**
 * Copyright 2021 Emmanuel Bourg
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
import java.security.KeyStoreException;
import java.security.Provider;
import java.security.ProviderException;
import java.util.ArrayList;
import java.util.List;

/**
 * Helper class for working with YubiKeys.
 *
 * @since 4.0
 */
class YubiKey {

    /**
     * Returns the security provider for the YubiKey.
     *
     * @return the YubiKey security provider
     * @throws KeyStoreException throws if the keystore cannot be loaded
     * @since 4.0
     */
    static Provider getProvider() {
        return ProviderUtils.createSunPKCS11Provider(getSunPKCS11Configuration());
    }

    /**
     * Returns the SunPKCS11 configuration of the YubiKey.
     *
     * @throws IllegalStateException thrown if the PKCS11 modules cannot be found
     * @since 4.0
     */
    static String getSunPKCS11Configuration() {
        File libykcs11 = getYkcs11Library();
        if (!libykcs11.exists()) {
            throw new ProviderException("YubiKey PKCS11 module (ykcs11) is not installed (" + libykcs11 + " is missing)");
        }
        return "--name=yubikey\nlibrary = " + libykcs11.getAbsolutePath();
    }

    /**
     * Attempts to locate the ykcs11 library on the system.
     *
     * @since 4.0
     */
    static File getYkcs11Library() {
        String osname = System.getProperty("os.name");
        String arch = System.getProperty("sun.arch.data.model");

        if (osname.contains("Windows")) {
            String programfiles;
            if ("32".equals(arch) && System.getenv("ProgramFiles(x86)") != null) {
                programfiles = System.getenv("ProgramFiles(x86)");
            } else {
                programfiles = System.getenv("ProgramFiles");
            }
            File libykcs11 = new File(programfiles + "/Yubico/Yubico PIV Tool/bin/libykcs11.dll");

            if (!System.getenv("PATH").contains("Yubico PIV Tool\\bin")) {
                System.out.println("WARNING: The YubiKey library path (" + libykcs11.getParentFile().getAbsolutePath().replace('/', '\\') + ") is missing from the PATH environment variable");
            }

            return libykcs11;

        } else if (osname.contains("Mac")) {
            return new File("/usr/local/lib/libykcs11.dylib");

        } else {
            // Linux
            List<String> paths = new ArrayList<>();
            if ("32".equals(arch)) {
                paths.add("/usr/lib/libykcs11.so");
                paths.add("/usr/lib/libykcs11.so.1");
                paths.add("/usr/lib/i386-linux-gnu/libykcs11.so");
                paths.add("/usr/lib/arm-linux-gnueabi/libykcs11.so");
                paths.add("/usr/lib/arm-linux-gnueabihf/libykcs11.so");
            } else {
                paths.add("/usr/lib64/libykcs11.so");
                paths.add("/usr/lib64/libykcs11.so.1");
                paths.add("/usr/lib/x86_64-linux-gnu/libykcs11.so");
                paths.add("/usr/lib/aarch64-linux-gnu/libykcs11.so");
                paths.add("/usr/lib/mips64el-linux-gnuabi64/libykcs11.so");
                paths.add("/usr/lib/riscv64-linux-gnu/libykcs11.so");
            }

            for (String path : paths) {
                File libykcs11 = new File(path);
                if (libykcs11.exists()) {
                    return libykcs11;
                }
            }

            return new File("/usr/local/lib/libykcs11.so");
        }
    }
}
