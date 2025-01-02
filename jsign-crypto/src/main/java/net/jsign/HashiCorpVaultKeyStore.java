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

import net.jsign.jca.HashiCorpVaultSigningService;
import net.jsign.jca.SigningServiceJcaProvider;
import org.kohsuke.MetaInfServices;

import java.security.Provider;

import static net.jsign.JsignKeyStore.getCertificateStore;

/**
 * HashiCorp Vault secrets engine (Transit or GCPKMS). The certificate must be provided separately. The keystore
 * parameter references the URL of the HashiCorp Vault secrets engine (<code>https://vault.example.com/v1/gcpkms</code>).
 * The alias parameter specifies the name of the key in Vault. For the Google Cloud KMS secrets engine, the version
 * of the Google Cloud key is appended to the key name, separated by a colon character. (<code>mykey:1</code>).
 */
@MetaInfServices(JsignKeyStore.class)
public class HashiCorpVaultKeyStore extends AbstractJsignKeyStore {
    @Override
    public String getType() {
        return "HASHICORPVAULT";
    }

    @Override
    public void validate(KeyStoreBuilder params) throws IllegalArgumentException {
        if (params.keystore() == null) {
            throw new IllegalArgumentException("keystore " + params.parameterName() + " must specify the HashiCorp Vault secrets engine URL");
        }
        if (params.storepass() == null) {
            throw new IllegalArgumentException("storepass " + params.parameterName() + " must specify the HashiCorp Vault token");
        }
        if (params.certfile() == null) {
            throw new IllegalArgumentException("certfile " + params.parameterName() + " must be set");
        }
    }

    @Override
    public Provider getProvider(KeyStoreBuilder params) {
        return new SigningServiceJcaProvider(new HashiCorpVaultSigningService(params.keystore(), params.storepass(), getCertificateStore(params)));
    }
}
