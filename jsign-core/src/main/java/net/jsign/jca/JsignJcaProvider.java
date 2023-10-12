/**
 * Copyright 2023 Emmanuel Bourg
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.jsign.jca;

import java.io.InputStream;
import java.security.AccessController;
import java.security.InvalidParameterException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.util.Enumeration;

import net.jsign.DigestAlgorithm;
import net.jsign.KeyStoreBuilder;
import net.jsign.KeyStoreType;

/**
 * JCA provider using a Jsign keystore and compatible with jarsigner.
 *
 * <p>The provider must be configured with the keystore parameter (the value depends on the keystore type).
 * The type of the keystore is one of the names from the {@link KeyStoreType} enum.</p>
 *
 * <p>Example:</p>
 * <pre>
 * Provider provider = new JsignJcaProvider();
 * provider.configure(vaultname)
 * KeyStore keystore = KeyStore.getInstance(AZUREKEYVAULT.name(), provider);
 * keystore.load(null, accessToken);
 * </pre>
 *
 * @since 5.1
 */
public class JsignJcaProvider extends Provider {

    private String keystore;

    public JsignJcaProvider() {
        super("Jsign", 1.0, "Jsign security provider");

        AccessController.doPrivileged((PrivilegedAction<Object>) () -> {
            for (KeyStoreType type : KeyStoreType.values()) {
                putService(new ProviderService(this, "KeyStore", type.name(), JsignJcaKeyStore.class.getName(), () -> new JsignJcaKeyStore(type, keystore)));
            }
            for (String alg : new String[]{"RSA", "ECDSA"}) {
                for (DigestAlgorithm digest : DigestAlgorithm.values()) {
                    if (digest != DigestAlgorithm.MD5) {
                        String algorithm = digest.name() + "with" + alg;
                        putService(new ProviderService(this, "Signature", algorithm, SigningServiceSignature.class.getName(), () -> new SigningServiceSignature(algorithm)));
                    }
                }
            }
            return null;
        });
    }

    public JsignJcaProvider(String configArg) {
        this();
        configure(configArg);
    }

    public Provider configure(String configArg) throws InvalidParameterException {
        this.keystore = configArg;

        return this;
    }

    static class JsignJcaKeyStore extends AbstractKeyStoreSpi {

        private KeyStoreBuilder builder = new KeyStoreBuilder();
        private KeyStore keystore;

        public JsignJcaKeyStore(KeyStoreType type, String keystore) {
            builder.storetype(type);
            builder.keystore(keystore);
            builder.certfile("");
        }

        private KeyStore getKeyStore() throws KeyStoreException {
            if (keystore == null) {
                keystore = builder.build();
            }

            return keystore;
        }

        @Override
        public Key engineGetKey(String alias, char[] password) throws UnrecoverableKeyException {
            if (password != null) {
                builder.keypass(new String(password));
            }
            try {
                return getKeyStore().getKey(alias, password);
            } catch (UnrecoverableKeyException e) {
                e.printStackTrace(); // because jarsigner swallows the root cause and hides what's going on
                throw e;
            } catch (KeyStoreException | NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            }
        }

        @Override
        public Certificate[] engineGetCertificateChain(String alias) {
            try {
                return getKeyStore().getCertificateChain(alias);
            } catch (KeyStoreException e) {
                return null;
            }
        }

        @Override
        public Enumeration<String> engineAliases() {
            try {
                return getKeyStore().aliases();
            } catch (KeyStoreException e) {
                throw new RuntimeException(e);
            }
        }

        @Override
        public void engineLoad(InputStream stream, char[] password) {
            if (password != null) {
                builder.storepass(new String(password));
            }
        }
    }
}
