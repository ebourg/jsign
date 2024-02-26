/*
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

package net.jsign;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Provider;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Objects;
import java.util.function.Function;

abstract class AbstractKeyStoreType implements KeyStoreType {

    public KeyStore getKeystore(KeyStoreBuilder params, Provider provider) throws KeyStoreException {
        KeyStore ks;
        try {
            if (provider != null) {
                ks = KeyStore.getInstance(name(), provider);
            } else {
                ks = KeyStore.getInstance(name());
            }
        } catch (KeyStoreException e) {
            throw new KeyStoreException("keystore type '" + name() + "' is not supported" + (provider != null ? " with security provider " + provider.getName() : ""), e);
        }

        try {
            boolean fileBased = this instanceof FileBasedKeyStoreType;
            try (FileInputStream in = fileBased ? new FileInputStream(params.createFile(params.keystore())) : null) {
                ks.load(in, params.storepass() != null ? params.storepass().toCharArray() : null);
            }
        } catch (Exception e) {
            throw new KeyStoreException("Unable to load the keystore " + params.keystore(), e);
        }

        return ks;
    }

    Function<String, Certificate[]> getCertificateStore(KeyStoreBuilder params) {
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

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof KeyStoreType)) {
            return false;
        }
        KeyStoreType that = (KeyStoreType) o;
        return Objects.equals(name(), that.name());
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(name());
    }
}
