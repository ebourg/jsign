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

import net.jsign.jca.DigiCertOneSigningService;
import net.jsign.jca.SigningServiceJcaProvider;
import org.kohsuke.MetaInfServices;

import java.security.Provider;

/**
 * DigiCert ONE. Certificates and keys stored in the DigiCert ONE Secure Software Manager can be used directly
 * without installing the DigiCert client tools. The API key, the PKCS#12 keystore holding the client certificate
 * and its password are combined to form the storepass parameter: <code>&lt;api-key&gt;|&lt;keystore&gt;|&lt;password&gt;</code>.
 */
@MetaInfServices(JsignKeyStore.class)
public class DigiCertOneKeyStore extends AbstractJsignKeyStore {
    @Override
    public String getType() {
        return "DIGICERTONE";
    }

    @Override
    public void validate(KeyStoreBuilder params) throws IllegalArgumentException {
        if (params.storepass() == null || params.storepass().split("\\|").length != 3) {
            throw new IllegalArgumentException("storepass " + params.parameterName() + " must specify the DigiCert ONE API key and the client certificate: <apikey>|<keystore>|<password>");
        }
    }

    @Override
    public Provider getProvider(KeyStoreBuilder params) {
        String[] elements = params.storepass().split("\\|");
        return new SigningServiceJcaProvider(new DigiCertOneSigningService(params.keystore(), elements[0], params.createFile(elements[1]), elements[2]));
    }
}
