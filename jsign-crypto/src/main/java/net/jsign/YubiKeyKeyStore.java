/*
 * Copyright 2024 Björn Kautler
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

import net.jsign.jca.AutoLoginProvider;
import org.kohsuke.MetaInfServices;
import sun.security.pkcs11.wrapper.PKCS11;
import sun.security.pkcs11.wrapper.PKCS11Exception;

import java.io.File;
import java.io.IOException;
import java.security.AuthProvider;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Provider;
import java.security.ProviderException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.logging.Logger;

/**
 * YubiKey PIV. This keystore requires the ykcs11 library from the <a href="https://developers.yubico.com/yubico-piv-tool/">Yubico PIV Tool</a>
 * to be installed at the default location. On Windows, the path to the library must be specified in the
 * <code>PATH</code> environment variable.
 */
@MetaInfServices(JsignKeyStore.class)
public class YubiKeyKeyStore extends Pkcs11KeyStore {
    @Override
    public String getType() {
        return "YUBIKEY";
    }

    @Override
    public Provider getProvider(KeyStoreBuilder params) {
        return new AutoLoginProvider((AuthProvider) ProviderUtils.createSunPKCS11Provider(getSunPKCS11Configuration()));
    }

    @Override
    public Set<String> getAliases(KeyStore keystore) throws KeyStoreException {
        Set<String> aliases = super.getAliases(keystore);
        // the attestation certificate is never used for signing
        aliases.remove("X.509 Certificate for PIV Attestation");
        return aliases;
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
        String configuration = "--name=yubikey\nlibrary = \"" + libykcs11.getAbsolutePath().replace("\\", "\\\\") + "\"\n";
        try {
            long slot = getTokenSlot(libykcs11);
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
    public static boolean isPresent() {
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
                Logger log = Logger.getLogger(YubiKeyKeyStore.class.getName());
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
