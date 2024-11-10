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

package net.jsign.jca;

import net.jsign.KeyStoreBuilder;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import java.net.HttpURLConnection;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.Base64;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * Credentials for the SignServer REST interface.
 *
 * @since 7.0
 */
public class SignServerCredentials {

    public String username;
    public String password;
    public KeyStore.Builder keystore;

    public SignServerCredentials(String username, String password, String keystore, String storepass) {
        this(username, password, keystore == null ? null : new KeyStoreBuilder().keystore(keystore).storepass(storepass).builder());
    }

    public SignServerCredentials(String username, String password, KeyStore.Builder keystore) {
        this.username = username;
        this.password = password;
        this.keystore = keystore;
    }

    void addAuthentication(HttpURLConnection conn) {
        if (conn instanceof HttpsURLConnection && keystore != null) {
            try {
                KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
                kmf.init(keystore.getKeyStore(), ((KeyStore.PasswordProtection) keystore.getProtectionParameter("")).getPassword());

                SSLContext context = SSLContext.getInstance("TLS");
                context.init(kmf.getKeyManagers(), null, new SecureRandom());
                ((HttpsURLConnection) conn).setSSLSocketFactory(context.getSocketFactory());
            } catch (GeneralSecurityException e) {
                throw new RuntimeException("Unable to load the SignServer client certificate", e);
            }
        }

        if (username != null) {
            conn.setRequestProperty(
                    "Authorization",
                    "Basic " + Base64.getEncoder().encodeToString((username + ":" + (password == null ? "" : password)).getBytes(UTF_8)));
        }
    }
}
