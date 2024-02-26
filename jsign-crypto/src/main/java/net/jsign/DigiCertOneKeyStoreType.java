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

import net.jsign.jca.DigiCertOneSigningService;
import net.jsign.jca.SigningServiceJcaProvider;

@MetaInfServices(KeyStoreType.class)
public class DigiCertOneKeyStoreType extends AbstractKeyStoreType {

    @Override
    public String name() {
        return "DIGICERTONE";
    }

    @Override
    public void validate(KeyStoreBuilder params) {
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
