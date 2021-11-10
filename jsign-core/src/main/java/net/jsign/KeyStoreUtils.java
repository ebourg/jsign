/**
 * Copyright 2017 Emmanuel Bourg
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
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Provider;

/**
 * Helper class for loading KeyStores (JKS, JCEKS, PKCS#12 or PKCS#11).
 * 
 * @author Emmanuel Bourg
 * @since 2.0
 */
public class KeyStoreUtils {

    private KeyStoreUtils() {
    }

    /**
     * Load the keystore from the specified file.
     * 
     * @param keystore   the file containing the keystore
     * @param storetype  the type of the keystore (either JKS, JCEKS, PKCS12 or PKCS11).
     *                   If null the type is inferred from the extension of the file (.p12 or .pfx for PKCS#12 keystores)
     * @param storepass  The password of the keystore
     * @param provider   The security provider used to load the keystore (must be specified for PKCS#11 keystores)
     * @return the keystore loaded
     * @throws KeyStoreException thrown if the keystore cannot be loaded
     */
    public static KeyStore load(File keystore, String storetype, String storepass, Provider provider) throws KeyStoreException {
        return load(keystore != null ? keystore.getPath() : null, storetype, storepass, provider);
    }

    /**
     * Load the keystore from the specified path.
     *
     * @param keystore   the path to the keystore
     * @param storetype  the type of the keystore (either JKS, JCEKS, PKCS12 or PKCS11).
     *                   If null the type is inferred from the extension of the file (.p12 or .pfx for PKCS#12 keystores)
     * @param storepass  The password of the keystore
     * @param provider   The security provider used to load the keystore (must be specified for PKCS#11 keystores)
     * @return the keystore loaded
     * @throws KeyStoreException thrown if the keystore cannot be loaded
     */
    public static KeyStore load(String keystore, String storetype, String storepass, Provider provider) throws KeyStoreException {
        if (keystore != null && storetype == null) {
            storetype = getType(keystore);
        }
        
        KeyStore ks;
        try {
            if (provider != null) {
                ks = KeyStore.getInstance(storetype, provider);
            } else {
                ks = KeyStore.getInstance(storetype);
            }
        } catch (KeyStoreException e) {
            throw new KeyStoreException("keystore type '" + storetype + "' is not supported", e);
        }

        boolean filebased = "JKS".equals(storetype) || "JCEKS".equals(storetype) || "PKCS12".equals(storetype);
        if (filebased && (keystore == null || !new File(keystore).exists())) {
            throw new KeyStoreException("The keystore " + keystore + " couldn't be found");
        }
        
        try {
            try (FileInputStream in = !filebased ? null : new FileInputStream(keystore)) {
                ks.load(in, storepass != null ? storepass.toCharArray() : null);
            }
        } catch (Exception e) {
            throw new KeyStoreException("Unable to load the keystore " + keystore, e);
        }
        
        return ks;
    }

    /**
     * Guess the type of the keystore from the header or the extension of the file.
     *
     * @param keystore   the path to the keystore
     */
    static String getType(String keystore) throws KeyStoreException {
        if (keystore == null) {
            return null;
        }

        // guess the type of the keystore from the header of the file
        File file = new File(keystore);
        if (file.exists()) {
            try (FileInputStream in = new FileInputStream(file)) {
                byte[] header = new byte[4];
                in.read(header);
                ByteBuffer buffer = ByteBuffer.wrap(header);
                if (buffer.get(0) == 0x30) {
                    return "PKCS12";
                } else if ((buffer.getInt(0) & 0xFFFFFFFFL) == 0xCECECECEL) {
                    return "JCEKS";
                } else if ((buffer.getInt(0) & 0xFFFFFFFFL) == 0xFEEDFEEDL) {
                    return "JKS";
                }
            } catch (IOException e) {
                throw new KeyStoreException("Unable to load the keystore " + keystore, e);
            }
        }

        // guess the type of the keystore from the extension of the file
        String filename = keystore.toLowerCase();
        if (filename.endsWith(".p12") || filename.endsWith(".pfx")) {
            return "PKCS12";
        } else if (filename.endsWith(".jceks")) {
            return "JCEKS";
        } else if (filename.endsWith(".jks")) {
            return "JKS";
        } else {
            return null;
        }
    }
}
