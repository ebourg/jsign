/*
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
import java.io.IOException;
import java.security.AuthProvider;
import java.security.Provider;
import java.security.ProviderException;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

import sun.security.pkcs11.wrapper.PKCS11;
import sun.security.pkcs11.wrapper.PKCS11Exception;

import net.jsign.jca.AutoLoginProvider;

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
     * @throws ProviderException thrown if the provider can't be initialized
     * @since 4.0
     */
    static Provider getProvider() {
        return new AutoLoginProvider((AuthProvider) ProviderUtils.createSunPKCS11Provider(getSunPKCS11Configuration()));
    }

    /**
     * Returns the SunPKCS11 configuration of the YubiKey.
     *
     * @throws ProviderException thrown if the PKCS11 modules cannot be found
     * @since 4.0
     */
    static String getSunPKCS11Configuration() {
        File libykcs11 = getYkcs11Library();
        if (!libykcs11.exists()) {
            throw new ProviderException("YubiKey PKCS11 module (ykcs11) is not installed (" + libykcs11 + " is missing)");
        }

        long slot;
        try {
            slot = getTokenSlot(libykcs11);
        } catch (Exception e) {
            throw new ProviderException(e);
        }

        return new PKCS11Configuration().name("yubikey").library(libykcs11).slot(slot).toString();
    }

    /**
     * Returns the slot index associated to the token.
     *
     * @since 4.1
     */
    static long getTokenSlot(File libraryPath) throws PKCS11Exception, IOException {
        PKCS11 pkcs11 = PKCS11.getInstance(libraryPath.getAbsolutePath(), "C_GetFunctionList", null, false);
        long[] slots = pkcs11.C_GetSlotList(true);
        return slots.length > 0 ? slots[0] : -1;
    }

    /**
     * Tells if a YubiKey is present on the system.
     */
    static boolean isPresent() {
        try {
            return getTokenSlot(getYkcs11Library()) >= 0;
        } catch (Exception e) {
            return false;
        }
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
                Logger log = Logger.getLogger(YubiKey.class.getName());
                log.warning("The YubiKey library path (" + libykcs11.getParentFile().getAbsolutePath().replace('/', '\\') + ") is missing from the PATH environment variable");
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
            String libraryPath = System.getenv("LD_LIBRARY_PATH");
            if (libraryPath != null) {
                for (String s : libraryPath.split(":")) {
                    paths.add(s + "/libykcs11.so");
                }
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
