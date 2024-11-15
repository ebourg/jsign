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

import org.kohsuke.MetaInfServices;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Provider;
import java.security.Security;

/**
 * PKCS#11 hardware token. The keystore parameter specifies either the name of the provider defined
 * in <code>jre/lib/security/java.security</code> or the path to the
 * <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/p11guide.html#Config">SunPKCS11 configuration file</a>.
 */
@MetaInfServices(JsignKeyStore.class)
public class Pkcs11KeyStore extends AbstractJsignKeyStore {
    @Override
    public String getType() {
        return "PKCS11";
    }

    @Override
    public void validate(KeyStoreBuilder params) throws IllegalArgumentException {
        if (params.keystore() == null) {
            throw new IllegalArgumentException("keystore " + params.parameterName() + " must be set");
        }
    }

    @Override
    public Provider getProvider(KeyStoreBuilder params) {
        // the keystore parameter is either the provider name or the SunPKCS11 configuration file
        if (params.createFile(params.keystore()).exists()) {
            return ProviderUtils.createSunPKCS11Provider(params.keystore());
        } else if (params.keystore().startsWith("SunPKCS11-")) {
            Provider provider = Security.getProvider(params.keystore());
            if (provider == null) {
                throw new IllegalArgumentException("Security provider " + params.keystore() + " not found");
            }
            return provider;
        } else {
            throw new IllegalArgumentException("keystore " + params.parameterName() + " should either refer to the SunPKCS11 configuration file or to the name of the provider configured in jre/lib/security/java.security");
        }
    }

    @Override
    public KeyStore getKeystore(KeyStoreBuilder params, Provider provider) throws KeyStoreException {
        KeyStore ks;
        try {
            if (provider != null) {
                ks = KeyStore.getInstance("PKCS11", provider);
            } else {
                ks = KeyStore.getInstance("PKCS11");
            }
        } catch (KeyStoreException e) {
            throw new KeyStoreException("keystore type '" + getType() + "' is not supported" + (provider != null ? " with security provider " + provider.getName() : ""), e);
        }

        try {
            ks.load(null, params.storepass() != null ? params.storepass().toCharArray() : null);
        } catch (Exception e) {
            throw new KeyStoreException("Unable to load the keystore " + params.keystore(), e);
        }

        return ks;
    }
}
