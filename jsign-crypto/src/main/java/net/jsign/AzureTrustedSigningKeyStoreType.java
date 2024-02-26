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

import net.jsign.jca.AzureTrustedSigningService;
import net.jsign.jca.SigningServiceJcaProvider;

@MetaInfServices(KeyStoreType.class)
public class AzureTrustedSigningKeyStoreType extends AbstractKeyStoreType {

    @Override
    public String name() {
        return "TRUSTEDSIGNING";
    }

    @Override
    public void validate(KeyStoreBuilder params) {
        if (params.keystore() == null) {
            throw new IllegalArgumentException("keystore " + params.parameterName() + " must specify the Azure endpoint (<region>.codesigning.azure.net)");
        }
        if (params.storepass() == null) {
            throw new IllegalArgumentException("storepass " + params.parameterName() + " must specify the Azure API access token");
        }
    }

    @Override
    public Provider getProvider(KeyStoreBuilder params) {
        return new SigningServiceJcaProvider(new AzureTrustedSigningService(params.keystore(), params.storepass()));
    }
}
