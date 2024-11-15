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

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Provider;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Set;
import java.util.function.Function;

public interface JsignKeyStore {

    /**
     * The keystore type identifier used to select a specific keystore type.
     */
    String getType();

    /**
     * Validates the keystore parameters.
     */
    void validate(KeyStoreBuilder params) throws IllegalArgumentException;

    /**
     * Returns the security provider to use the keystore.
     */
    Provider getProvider(KeyStoreBuilder params);

    /**
     * Build the keystore.
     */
    KeyStore getKeystore(KeyStoreBuilder params, Provider provider) throws KeyStoreException;

    /**
     * Returns the aliases of the keystore available for signing.
     */
    Set<String> getAliases(KeyStore keystore) throws KeyStoreException;

    static Function<String, Certificate[]> getCertificateStore(KeyStoreBuilder params) {
        return alias -> {
            if (alias == null || alias.isEmpty()) {
                return null;
            }

            try {
                return CertificateUtils.loadCertificateChain(params.certfile());
            } catch (IOException | CertificateException e) {
                throw new RuntimeException("Failed to load the certificate from " + params.certfile(), e);
            }
        };
    }
}
