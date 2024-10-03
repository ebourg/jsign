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
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Provider;

/**
 * Helper class for loading KeyStores (JKS, JCEKS, PKCS#12 or PKCS#11).
 * 
 * @author Emmanuel Bourg
 * @since 2.0
 * @deprecated Use {@link KeyStoreBuilder} instead
 */
public class KeyStoreUtils {

    private KeyStoreUtils() {
    }

    /**
     * Load the keystore from the specified file.
     *
     * @param keystore   the file containing the keystore
     * @param storetype  the type of the keystore
     *                   If null the type is inferred from the extension of the file (.p12 or .pfx for PKCS#12 keystores)
     * @param storepass  The password of the keystore
     * @param provider   The security provider used to load the keystore (must be specified for PKCS#11 keystores)
     * @return the keystore loaded
     * @throws KeyStoreException thrown if the keystore cannot be loaded
     */
    public static KeyStore load(File keystore, String storetype, String storepass, Provider provider) throws KeyStoreException {
        KeyStoreBuilder params = new KeyStoreBuilder().keystore(keystore).storetype(storetype).storepass(storepass);
        params.validate();
        return params.storetype().getKeystore(params, provider);
    }

    /**
     * Load the keystore from the specified path.
     *
     * @param keystore   the path to the keystore
     * @param storetype  the type of the keystore
     *                   If null the type is inferred from the extension of the file (.p12 or .pfx for PKCS#12 keystores)
     * @param storepass  The password of the keystore
     * @param provider   The security provider used to load the keystore (must be specified for PKCS#11 keystores)
     * @return the keystore loaded
     * @throws KeyStoreException thrown if the keystore cannot be loaded
     */
    public static KeyStore load(String keystore, String storetype, String storepass, Provider provider) throws KeyStoreException {
        KeyStoreBuilder params = new KeyStoreBuilder().keystore(keystore).storetype(storetype).storepass(storepass);
        params.validate();
        return params.storetype().getKeystore(params, provider);
    }
}
