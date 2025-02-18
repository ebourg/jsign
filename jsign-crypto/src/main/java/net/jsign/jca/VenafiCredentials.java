/*
 * Copyright 2025 Ivan Wallis
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
 * Credentials for the Venafi CodeSign Protect.
 *
 * @since 7.2
 */
public class VenafiCredentials {

    public String username;
    public String password;
    public KeyStore.Builder keystore;
    public String sessionToken;

    public VenafiCredentials(String username, String password, String keystore, String storepass) {
        this(username, password, new KeyStoreBuilder().keystore(keystore).storepass(storepass).builder());
    }

    public VenafiCredentials(String username, String password, KeyStore.Builder keystore) {
        this.username = username;
        this.password = password;
        this.keystore = keystore;
    }

    public String getSessionToken(String endpoint) throws IOException {
        if (sessionToken == null) {
            RESTClient client = new RESTClient(endpoint)
                    .errorHandler(response -> response.get("error") + ": " + response.get("error_description"));

            Map<String, Object> request = new LinkedHashMap<>();    
            request.put("client_id", "VenafiCodeSignClient");
            request.put("scope", "codesignclient");
            if (username != null && password != null) {
                request.put("username", username);
                request.put("password", password);
            }

            Map<String, ?> response = client.post("/vedauth/authorize/oauth", JsonWriter.format(request));
            sessionToken = (String) response.get("access_token");
        }

        return sessionToken;
    }
}
