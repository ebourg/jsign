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
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.LinkedHashMap;
import java.util.Map;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;

import net.jsign.KeyStoreBuilder;

/**
 * Credentials for the Garantir Remote Signing service.
 *
 * @since 7.0
 */
public class GaraSignCredentials {

    public String username;
    public String password;
    public KeyStore.Builder keystore;
    public String sessionToken;

    public GaraSignCredentials(String username, String password, String keystore, String storepass) {
        this(username, password, new KeyStoreBuilder().keystore(keystore).storepass(storepass).builder());
    }

    public GaraSignCredentials(String username, String password, KeyStore.Builder keystore) {
        this.username = username;
        this.password = password;
        this.keystore = keystore;
    }

    public String getSessionToken(String endpoint) throws IOException {
        if (sessionToken == null) {
            RESTClient client = new RESTClient(endpoint)
                    .authentication((conn, data) -> {
                        if (conn instanceof HttpsURLConnection && keystore != null) {
                            try {
                                KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
                                kmf.init(keystore.getKeyStore(), ((KeyStore.PasswordProtection) keystore.getProtectionParameter("")).getPassword());

                                SSLContext context = SSLContext.getInstance("TLS");
                                context.init(kmf.getKeyManagers(), null, new SecureRandom());
                                ((HttpsURLConnection) conn).setSSLSocketFactory(context.getSocketFactory());
                            } catch (GeneralSecurityException e) {
                                throw new RuntimeException("Unable to load the GaraSign client certificate", e);
                            }
                        }
                    });

            Map<String, String> params = new LinkedHashMap<>();
            params.put("api_version", "1.0");
            if (username != null && password != null) {
                params.put("username", username);
                params.put("password", password);
            }

            Map<String, ?> response = client.post("/authenticate", params);
            String status = (String) response.get("status");
            if (!"SUCCESS".equals(status)) {
                throw new IOException("Failed to authenticate with GaraSign: " + response.get("message"));
            }
            sessionToken = (String) response.get("sessionToken");
        }

        return sessionToken;
    }
}
