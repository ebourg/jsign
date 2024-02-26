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

package net.jsign;

import java.security.Provider;

import org.kohsuke.MetaInfServices;

import net.jsign.jca.HashiCorpVaultSigningService;
import net.jsign.jca.SigningServiceJcaProvider;

@MetaInfServices(KeyStoreType.class)
public class HashiCorpVaultKeyStoreType extends AbstractKeyStoreType {

    @Override
    public String name() {
        return "HASHICORPVAULT";
    }

    @Override
    public void validate(KeyStoreBuilder params) {
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
