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

package net.jsign.jca;

import java.io.IOException;
import java.io.InputStream;
import java.security.AuthProvider;
import java.security.Key;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Enumeration;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.login.LoginException;

/**
 * Security provider calling automatically the <code>login()</code> method of the underlying provider password before
 * signing. It is designed to avoid the <code>CKR_USER_NOT_LOGGED_IN</code> error when signing multiple times with the
 * ykcs11 PKCS#11 module for the Yubikey.
 *
 * @since 7.0
 */
public class AutoLoginProvider extends Provider {

    private final AuthProvider provider;

    private char[] storepass;

    public AutoLoginProvider(AuthProvider provider) {
        super(provider.getName(), provider.getVersion(), provider.getInfo() + " with auto login");
        this.provider = provider;
    }

    @Override
    public Service getService(String type, String algorithm) {
        if ("KeyStore".equals(type)) {
            return new PasswordInterceptorService(provider.getService(type, algorithm));
        } else if ("Signature".equals(type) && storepass != null) {
            login();
        }

        return provider.getService(type, algorithm);
    }

    private void login() {
        // logout and login again to avoid the CKR_USER_NOT_LOGGED_IN error with the Yubikey PKCS#11 provider
        try {
            provider.logout();
            provider.login(null, callbacks -> {
                for (Callback callback : callbacks) {
                    if (callback instanceof PasswordCallback) {
                        ((PasswordCallback) callback).setPassword(storepass);
                    }
                }
            });
        } catch (LoginException e) {
            // ignore the CKR_USER_NOT_LOGGED_IN error thrown when the user isn't logged in
        }
    }

    class PasswordInterceptorService extends Service {
        private final Service service;

        public PasswordInterceptorService(Service service) {
            super(AutoLoginProvider.this, service.getType(), service.getAlgorithm(), service.getClassName(), null, null);
            this.service = service;
        }

        @Override
        public Object newInstance(Object constructorParameter) throws NoSuchAlgorithmException {
            return new PasswordInterceptorKeyStoreSpi((KeyStoreSpi) service.newInstance(constructorParameter));
        }
    }

    class PasswordInterceptorKeyStoreSpi extends AbstractKeyStoreSpi {
        private final KeyStoreSpi instance;

        public PasswordInterceptorKeyStoreSpi(KeyStoreSpi instance) {
            this.instance = instance;
        }

        @Override
        public void engineLoad(InputStream stream, char[] password) throws IOException, NoSuchAlgorithmException, CertificateException {
            storepass = password;
            instance.engineLoad(stream, password);
        }

        @Override
        public Key engineGetKey(String alias, char[] password) throws NoSuchAlgorithmException, UnrecoverableKeyException {
            return instance.engineGetKey(alias, password);
        }

        @Override
        public Certificate[] engineGetCertificateChain(String alias) {
            return instance.engineGetCertificateChain(alias);
        }

        @Override
        public Enumeration<String> engineAliases() {
            return instance.engineAliases();
        }
    }
}
