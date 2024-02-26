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

import java.io.File;
import java.io.IOException;
import java.security.Provider;

import org.kohsuke.MetaInfServices;

import net.jsign.jca.OracleCloudCredentials;
import net.jsign.jca.OracleCloudSigningService;
import net.jsign.jca.SigningServiceJcaProvider;

@MetaInfServices(KeyStoreType.class)
public class OracleCloudKeyStoreType extends AbstractKeyStoreType {

    @Override
    public String name() {
        return "ORACLECLOUD";
    }

    @Override
    public void validate(KeyStoreBuilder params) {
        if (params.certfile() == null) {
            throw new IllegalArgumentException("certfile " + params.parameterName() + " must be set");
        }
    }

    @Override
    public Provider getProvider(KeyStoreBuilder params) {
        OracleCloudCredentials credentials = new OracleCloudCredentials();
        try {
            File config = null;
            String profile = null;
            if (params.storepass() != null) {
                String[] elements = params.storepass().split("\\|", 2);
                config = new File(elements[0]);
                if (elements.length > 1) {
                    profile = elements[1];
                }
            }
            credentials.load(config, profile);
            credentials.loadFromEnvironment();
            if (params.keypass() != null) {
                credentials.setPassphrase(params.keypass());
            }
        } catch (IOException e) {
            throw new RuntimeException("An error occurred while fetching the Oracle Cloud credentials", e);
        }
        return new SigningServiceJcaProvider(new OracleCloudSigningService(credentials, getCertificateStore(params)));
    }
}
