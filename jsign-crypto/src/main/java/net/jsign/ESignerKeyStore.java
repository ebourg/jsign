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

import net.jsign.jca.ESignerSigningService;
import net.jsign.jca.SigningServiceJcaProvider;
import org.kohsuke.MetaInfServices;

import java.io.IOException;
import java.security.Provider;

/**
 * SSL.com eSigner. The SSL.com username and password are used as the keystore password (<code>&lt;username&gt;|&lt;password&gt;</code>),
 * and the base64 encoded TOTP secret is used as the key password.
 */
@MetaInfServices(JsignKeyStore.class)
public class ESignerKeyStore extends AbstractJsignKeyStore {
    @Override
    public String getType() {
        return "ESIGNER";
    }

    @Override
    public void validate(KeyStoreBuilder params) throws IllegalArgumentException {
        if (params.storepass() == null || !params.storepass().contains("|")) {
            throw new IllegalArgumentException("storepass " + params.parameterName() + " must specify the SSL.com username and password: <username>|<password>");
        }
    }

    @Override
    public Provider getProvider(KeyStoreBuilder params) {
        String[] elements = params.storepass().split("\\|", 2);
        String endpoint = params.keystore() != null ? params.keystore() : "https://cs.ssl.com";
        try {
            return new SigningServiceJcaProvider(new ESignerSigningService(endpoint, elements[0], elements[1]));
        } catch (IOException e) {
            throw new IllegalStateException("Authentication failed with SSL.com", e);
        }
    }
}
