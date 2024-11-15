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

import net.jsign.jca.GaraSignCredentials;
import net.jsign.jca.GaraSignSigningService;
import net.jsign.jca.SigningServiceJcaProvider;
import org.kohsuke.MetaInfServices;

import java.security.Provider;

@MetaInfServices(JsignKeyStore.class)
public class GaraSignKeyStore extends AbstractJsignKeyStore {
    @Override
    public String getType() {
        return "GARASIGN";
    }

    @Override
    public void validate(KeyStoreBuilder params) throws IllegalArgumentException {
        if (params.storepass() == null || params.storepass().split("\\|").length > 3) {
            throw new IllegalArgumentException("storepass " + params.parameterName() + " must specify the GaraSign username/password and/or the path to the keystore containing the TLS client certificate: <username>|<password>, <certificate>, or <username>|<password>|<certificate>");
        }
    }

    @Override
    public Provider getProvider(KeyStoreBuilder params) {
        String[] elements = params.storepass().split("\\|");
        String username = null;
        String password = null;
        String certificate = null;
        if (elements.length == 1) {
            certificate = elements[0];
        } else if (elements.length == 2) {
            username = elements[0];
            password = elements[1];
        } else if (elements.length == 3) {
            username = elements[0];
            password = elements[1];
            certificate = elements[2];
        }

        GaraSignCredentials credentials = new GaraSignCredentials(username, password, certificate, params.keypass());
        return new SigningServiceJcaProvider(new GaraSignSigningService(params.keystore(), credentials));
    }
}
