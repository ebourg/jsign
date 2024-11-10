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

import net.jsign.jca.SignServerCredentials;
import net.jsign.jca.SignServerSigningService;
import net.jsign.jca.SigningServiceJcaProvider;
import org.kohsuke.MetaInfServices;

import java.security.Provider;

/**
 * Keyfactor SignServer. This keystore requires a Plain Signer worker configured to allow client-side hashing (with
 * the properties <code>CLIENTSIDEHASHING</code> or <code>ALLOW_CLIENTSIDEHASHING_OVERRIDE</code> set to true), and
 * the <code>SIGNATUREALGORITHM</code> property set to <code>NONEwithRSA</code> or <code>NONEwithECDSA</code>.
 *
 * <p>The authentication is performed by specifying the username/password or the TLS client certificate in the
 * storepass parameter. If the TLS client certificate is stored in a password protected keystore, the password is
 * specified in the keypass parameter. The keystore parameter references the URL of the SignServer REST API. The
 * alias parameter specifies the id or the name of the worker.</p>
 */
@MetaInfServices(JsignKeyStore.class)
public class SignServerKeyStore extends AbstractJsignKeyStore {
    @Override
    public String getType() {
        return "SIGNSERVER";
    }

    @Override
    public void validate(KeyStoreBuilder params) throws IllegalArgumentException {
        if (params.keystore() == null) {
            throw new IllegalArgumentException("keystore " + params.parameterName() + " must specify the SignServer API endpoint (e.g. https://example.com/signserver/)");
        }
        if (params.storepass() != null && params.storepass().split("\\|").length > 2) {
            throw new IllegalArgumentException("storepass " + params.parameterName() + " must specify the SignServer username/password or the path to the keystore containing the TLS client certificate: <username>|<password> or <certificate>");
        }
    }

    @Override
    public Provider getProvider(KeyStoreBuilder params) {
        String username = null;
        String password = null;
        String certificate = null;
        if (params.storepass() != null) {
            String[] elements = params.storepass().split("\\|");
            if (elements.length == 1) {
                certificate = elements[0];
            } else if (elements.length == 2) {
                username = elements[0];
                password = elements[1];
            }
        }

        SignServerCredentials credentials = new SignServerCredentials(username, password, certificate, params.keypass());
        return new SigningServiceJcaProvider(new SignServerSigningService(params.keystore(), credentials));
    }
}
