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

import net.jsign.jca.AzureKeyVaultSigningService;
import net.jsign.jca.SigningServiceJcaProvider;
import org.kohsuke.MetaInfServices;

import java.security.Provider;

/**
 * Azure Key Vault. The keystore parameter specifies the name of the key vault, either the short name
 * (e.g. <code>myvault</code>), or the full URL (e.g. <code>https://myvault.vault.azure.net</code>).
 * The Azure API access token is used as the keystore password.
 */
@MetaInfServices(JsignKeyStore.class)
public class AzureKeyVaultKeyStore extends AbstractJsignKeyStore {
    @Override
    public String getType() {
        return "AZUREKEYVAULT";
    }

    @Override
    public void validate(KeyStoreBuilder params) throws IllegalArgumentException {
        if (params.keystore() == null) {
            throw new IllegalArgumentException("keystore " + params.parameterName() + " must specify the Azure vault name");
        }
        if (params.storepass() == null) {
            throw new IllegalArgumentException("storepass " + params.parameterName() + " must specify the Azure API access token");
        }
    }

    @Override
    public Provider getProvider(KeyStoreBuilder params) {
        return new SigningServiceJcaProvider(new AzureKeyVaultSigningService(params.keystore(), params.storepass()));
    }
}
