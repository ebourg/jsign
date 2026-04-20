/*
 * Copyright 2026 Emmanuel Bourg
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
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;

import net.jsign.KeyStoreBuilder;

/**
 * Credentials for Encryption Consulting CodeSign Secure.
 *
 * @since 7.5
 */
public class CodeSignSecureCredentials {

    private final String user;
    private final String code;
    private final KeyStore.Builder keystore;
    private String token;
    private SSLContext context;

    public CodeSignSecureCredentials(String user, String code, String keystore, String storepass) {
        this(user, code, new KeyStoreBuilder().keystore(keystore).storepass(storepass).builder());
    }

    public CodeSignSecureCredentials(String user, String code, KeyStore.Builder keystore) {
        this.user = user;
        this.code = code;
        this.keystore = keystore;
    }

    public String getToken(String endpoint) throws IOException {
        if (token == null) {
            RESTClient client = new RESTClient(endpoint);

            Map<String, Object> params = new LinkedHashMap<>();
            params.put("user", user);
            params.put("code", code);
            params.put("identityType", 1);

            Map<String, ?> response = client.post("/api/auth/GetLoginToken/", JsonWriter.format(params));
            token = (String) response.get("token");
        }

        return token;
    }

    /**
     * Returns the SSL context for the client authentication with the CodeSign Secure API.
     */
    SSLContext getSSLContext() throws GeneralSecurityException {
        if (context == null && keystore != null) {
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keystore.getKeyStore(), ((KeyStore.PasswordProtection) keystore.getProtectionParameter("")).getPassword());

            context = SSLContext.getInstance("TLS");
            context.init(kmf.getKeyManagers(), null, new SecureRandom());
            return context;
        }

        return context;
    }
}
