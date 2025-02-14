/*
 * Copyright 2023 Emmanuel Bourg
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
import java.security.Provider;
import java.security.ProviderException;
import java.util.ArrayList;
import java.util.List;

import sun.security.pkcs11.wrapper.PKCS11;
import sun.security.pkcs11.wrapper.PKCS11Exception;

/**
 * Helper class for working with SafeNet eTokens.
 *
 * @since 6.0
 */
class SafeNetEToken {

    /**
     * Returns the security provider for the SafeNet eToken.
     *
     * @return the SafeNet eTokens security provider
     * @throws ProviderException thrown if the provider can't be initialized
     */
    static Provider getProvider() {
        return ProviderUtils.createSunPKCS11Provider(getSunPKCS11Configuration());
    }

    /**
     * Returns the SunPKCS11 configuration of the SafeNet eToken.
     *
     * @throws ProviderException thrown if the PKCS11 modules cannot be found
     */
    static String getSunPKCS11Configuration() {
        File library = getPKCS11Library();
        if (!library.exists()) {
            throw new ProviderException("SafeNet eToken PKCS11 module is not installed (" + library + " is missing)");
        }
        String configuration = "--name=\"SafeNet eToken\"\nlibrary = \"" + library.getAbsolutePath().replace("\\", "\\\\") + "\"\n";
        try {
            long slot = getTokenSlot(library);
            if (slot >= 0) {
                configuration += "slot=" + slot;
            }
        } catch (Exception e) {
            throw new ProviderException(e);
        }
        return configuration;
    }

    /**
     * Returns the slot index associated to the token.
     */
    static long getTokenSlot(File libraryPath) throws PKCS11Exception, IOException {
        PKCS11 pkcs11 = PKCS11.getInstance(libraryPath.getAbsolutePath(), "C_GetFunctionList", null, false);
        long[] slots = pkcs11.C_GetSlotList(true);
        return slots.length > 0 ? slots[0] : -1;
    }

    /**
     * Attempts to locate the SafeNet eToken PKCS11 library on the system.
     */
    static File getPKCS11Library() {
        String osname = System.getProperty("os.name");
        String arch = System.getProperty("sun.arch.data.model");

        if (osname.contains("Windows")) {
            return new File(System.getenv("windir") + "/system32/eTPKCS11.dll");

        } else if (osname.contains("Mac")) {
            return new File("/usr/local/lib/libeTPkcs11.dylib");

        } else {
            // Linux
            List<String> paths = new ArrayList<>();
            if ("64".equals(arch)) {
                paths.add("/usr/lib64/pkcs11/libeTPkcs11.so");
                paths.add("/usr/lib64/libeTPkcs11.so");
                paths.add("/usr/lib64/libeToken.so");
            }
            paths.add("/usr/lib/pkcs11/libeTPkcs11.so");
            paths.add("/usr/lib/pkcs11/libeToken.so");
            paths.add("/usr/lib/libeTPkcs11.so");
            paths.add("/usr/lib/libeToken.so");

            for (String path : paths) {
                File library = new File(path);
                if (library.exists()) {
                    return library;
                }
            }

            return new File("/usr/local/lib/libeToken.so");
        }
    }
}
