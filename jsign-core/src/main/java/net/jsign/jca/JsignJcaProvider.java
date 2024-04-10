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
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.util.Enumeration;

import net.jsign.DigestAlgorithm;
import net.jsign.KeyStoreBuilder;
import net.jsign.KeyStoreType;

/**
 * JCA provider using a Jsign keystore and compatible with jarsigner and apksigner.
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
 *
 * PrivateKey key = (PrivateKey) keystore.getKey(alias, null);
 *
 * Signature signature = Signature.getInstance("SHA256withRSA", provider);
 * signature.initSign(key);
 * signature.update("Lorem ipsum dolor sit amet".getBytes());
 * signature.sign();
 * </pre>
 *
 * @since 6.0
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
                        putService(new ProviderService(this, "Signature", algorithm, JsignJcaSignature.class.getName(), () -> new JsignJcaSignature(algorithm)));
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
            String certfile = System.getProperty("jsign.certfile");
            if (certfile == null) {
                builder.certfile("");
            } else {
                builder.certfile(certfile);
            }
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
                return new JsignJcaPrivateKey((PrivateKey) getKeyStore().getKey(alias, password), builder.provider());
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

    static class JsignJcaPrivateKey implements PrivateKey {

        private final PrivateKey privateKey;
        private final Provider provider;

        public JsignJcaPrivateKey(PrivateKey key, Provider provider) {
            this.privateKey = key;
            this.provider = provider;
        }

        @Override
        public String getAlgorithm() {
            return privateKey.getAlgorithm();
        }

        @Override
        public String getFormat() {
            return privateKey.getFormat();
        }

        @Override
        public byte[] getEncoded() {
            return privateKey.getEncoded();
        }

        public PrivateKey getPrivateKey() {
            return privateKey;
        }

        public Provider getProvider() {
            return provider;
        }
    }

    static class JsignJcaSignature extends AbstractSignatureSpi {

        private Signature signature;

        public JsignJcaSignature(String signingAlgorithm) {
            super(signingAlgorithm);
        }

        @Override
        protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
            JsignJcaPrivateKey key = (JsignJcaPrivateKey) privateKey;

            try {
                signature = Signature.getInstance(signingAlgorithm, key.getProvider());
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            }
            signature.initSign(key.getPrivateKey());
        }

        @Override
        protected void engineUpdate(byte b) throws SignatureException {
            signature.update(b);
        }

        @Override
        protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
            signature.update(b, off, len);
        }

        @Override
        protected byte[] engineSign() throws SignatureException {
            return signature.sign();
        }
    }
}
