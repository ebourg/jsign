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

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Provider;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

public abstract class AbstractJsignKeyStore implements JsignKeyStore {
    @Override
    public void validate(KeyStoreBuilder params) throws IllegalArgumentException {
    }

    @Override
    public Provider getProvider(KeyStoreBuilder params) {
        return null;
    }

    @Override
    public KeyStore getKeystore(KeyStoreBuilder params, Provider provider) throws KeyStoreException  {
        KeyStore ks;
        try {
            if (provider != null) {
                ks = KeyStore.getInstance(getType(), provider);
            } else {
                ks = KeyStore.getInstance(getType());
            }
        } catch (KeyStoreException e) {
            throw new KeyStoreException("keystore type '" + getType() + "' is not supported" + (provider != null ? " with security provider " + provider.getName() : ""), e);
        }

        try {
            boolean fileBased = this instanceof FileBasedKeyStore;
            try (FileInputStream in = fileBased ? new FileInputStream(params.createFile(params.keystore())) : null) {
                ks.load(in, params.storepass() != null ? params.storepass().toCharArray() : null);
            }
        } catch (Exception e) {
            throw new KeyStoreException("Unable to load the keystore " + params.keystore(), e);
        }

        return ks;
    }

    @Override
    public Set<String> getAliases(KeyStore keystore) throws KeyStoreException {
        return new LinkedHashSet<>(Collections.list(keystore.aliases()));
    }
}
