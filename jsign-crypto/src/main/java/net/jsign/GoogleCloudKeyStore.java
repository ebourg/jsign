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

import net.jsign.jca.GoogleCloudSigningService;
import net.jsign.jca.SigningServiceJcaProvider;
import org.kohsuke.MetaInfServices;

import java.security.Provider;

import static net.jsign.JsignKeyStore.getCertificateStore;

/**
 * Google Cloud KMS. Google Cloud KMS stores only the private key, the certificate must be provided separately.
 * The keystore parameter references the path of the keyring. The alias can specify either the full path of the key,
 * or only the short name. If the version is omitted the most recent one will be picked automatically.
 */
@MetaInfServices(JsignKeyStore.class)
public class GoogleCloudKeyStore extends AbstractJsignKeyStore {
    @Override
    public String getType() {
        return "GOOGLECLOUD";
    }

    @Override
    public void validate(KeyStoreBuilder params) throws IllegalArgumentException {
        if (params.keystore() == null) {
            throw new IllegalArgumentException("keystore " + params.parameterName() + " must specify the Goole Cloud keyring");
        }
        if (!params.keystore().matches("projects/[^/]+/locations/[^/]+/keyRings/[^/]+")) {
            throw new IllegalArgumentException("keystore " + params.parameterName() + " must specify the path of the keyring (projects/{projectName}/locations/{location}/keyRings/{keyringName})");
        }
        if (params.storepass() == null) {
            throw new IllegalArgumentException("storepass " + params.parameterName() + " must specify the Goole Cloud API access token");
        }
        if (params.certfile() == null) {
            throw new IllegalArgumentException("certfile " + params.parameterName() + " must be set");
        }
    }

    @Override
    public Provider getProvider(KeyStoreBuilder params) {
        return new SigningServiceJcaProvider(new GoogleCloudSigningService(params.keystore(), params.storepass(), getCertificateStore(params)));
    }
}
