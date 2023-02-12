/**
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

import sun.security.pkcs11.wrapper.CK_SLOT_INFO;
import sun.security.pkcs11.wrapper.PKCS11;
import sun.security.pkcs11.wrapper.PKCS11Exception;

/**
 * Helper class for working with OpenSC.
 *
 * @since 4.3
 */
class OpenSC {

    /**
     * Returns the security provider for OpenSC.
     *
     * @param name the name of the token
     * @return the OpenSC security provider
     * @throws ProviderException thrown if the provider can't be initialized
     */
    static Provider getProvider(String name) {
        return ProviderUtils.createSunPKCS11Provider(getSunPKCS11Configuration(name));
    }

    /**
     * Returns the SunPKCS11 configuration for OpenSC.
     *
     * @param name the name of the token
     * @throws ProviderException thrown if the PKCS11 modules cannot be found
     */
    static String getSunPKCS11Configuration(String name) {
        File libpkcs11 = getOpenSCLibrary();
        if (!libpkcs11.exists()) {
            throw new ProviderException("OpenSC PKCS11 module is not installed (" + libpkcs11 + " is missing)");
        }
        String configuration = "--name=opensc\nlibrary = \"" + libpkcs11.getAbsolutePath().replace("\\", "\\\\") + "\"\n";
        try {
            long slot = getTokenSlot(libpkcs11, name);
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
     *
     * @param libraryPath the path to the PKCS11 library
     * @param name        the partial name of the token
     */
    static long getTokenSlot(File libraryPath, String name) throws PKCS11Exception, IOException {
        PKCS11 pkcs11 = PKCS11.getInstance(libraryPath.getAbsolutePath(), "C_GetFunctionList", null, false);
        long[] slots = pkcs11.C_GetSlotList(true);

        List<String> descriptions = new ArrayList<>();
        List<Long> matches = new ArrayList<>();
        for (long slot : slots) {
            CK_SLOT_INFO info = pkcs11.C_GetSlotInfo(slot);
            String description = new String(info.slotDescription).trim();
            if (name == null || description.toLowerCase().contains(name.toLowerCase())) {
                matches.add(slot);
            }
            descriptions.add(description);
        }

        if (matches.size() == 1) {
            return matches.get(0);
        }

        if (matches.isEmpty()) {
            throw new RuntimeException(descriptions.isEmpty() ? "No PKCS11 token found" : "No PKCS11 token found matching '" + name + "' (available tokens: " + String.join(", ", descriptions) + ")");
        } else {
            throw new RuntimeException("Multiple PKCS11 tokens found" + (name != null ? " matching '" + name + "'" : "") + ", please specify the name of the token to use (available tokens: " + String.join(", ", descriptions) + ")");
        }
    }

    /**
     * Attempts to locate the opensc-pkcs11 library on the system.
     */
    static File getOpenSCLibrary() {
        String osname = System.getProperty("os.name");
        String arch = System.getProperty("sun.arch.data.model");

        if (osname.contains("Windows")) {
            String programfiles;
            if ("32".equals(arch) && System.getenv("ProgramFiles(x86)") != null) {
                programfiles = System.getenv("ProgramFiles(x86)");
            } else {
                programfiles = System.getenv("ProgramFiles");
            }
            return new File(programfiles + "/OpenSC Project/OpenSC/pkcs11/opensc-pkcs11.dll");

        } else if (osname.contains("Mac")) {
            return new File("/Library/OpenSC/lib/opensc-pkcs11.so");

        } else {
            // Linux
            List<String> paths = new ArrayList<>();
            if ("32".equals(arch)) {
                paths.add("/usr/lib/opensc-pkcs11.so");
                paths.add("/usr/lib/i386-linux-gnu/opensc-pkcs11.so");
                paths.add("/usr/lib/arm-linux-gnueabi/opensc-pkcs11.so");
                paths.add("/usr/lib/arm-linux-gnueabihf/opensc-pkcs11.so");
            } else {
                paths.add("/usr/lib64/opensc-pkcs11.so");
                paths.add("/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so");
                paths.add("/usr/lib/aarch64-linux-gnu/opensc-pkcs11.so");
                paths.add("/usr/lib/mips64el-linux-gnuabi64/opensc-pkcs11.so");
                paths.add("/usr/lib/riscv64-linux-gnu/opensc-pkcs11.so");
            }

            for (String path : paths) {
                File libpkcs11 = new File(path);
                if (libpkcs11.exists()) {
                    return libpkcs11;
                }
            }

            return new File("/usr/local/lib/opensc-pkcs11.so");
        }
    }
}
