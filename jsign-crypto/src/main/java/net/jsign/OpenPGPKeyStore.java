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

import net.jsign.jca.OpenPGPCardSigningService;
import net.jsign.jca.SigningServiceJcaProvider;
import org.kohsuke.MetaInfServices;

import javax.smartcardio.CardException;
import java.security.Provider;

import static net.jsign.JsignKeyStore.getCertificateStore;

/**
 * OpenPGP card. OpenPGP cards contain up to 3 keys, one for signing, one for encryption, and one for authentication.
 * All of them can be used for code signing (except encryption keys based on an elliptic curve). The alias
 * to select the key is either, <code>SIGNATURE</code>, <code>ENCRYPTION</code> or <code>AUTHENTICATION</code>.
 * This keystore can be used with a Nitrokey (non-HSM models) or a Yubikey. If multiple devices are connected,
 * the keystore parameter can be used to specify the name of the one to use. This keystore type doesn't require
 * any external library to be installed.
 */
@MetaInfServices(JsignKeyStore.class)
public class OpenPGPKeyStore extends AbstractJsignKeyStore {
    @Override
    public String getType() {
        return "OPENPGP";
    }

    @Override
    public void validate(KeyStoreBuilder params) throws IllegalArgumentException {
        if (params.storepass() == null) {
            throw new IllegalArgumentException("storepass " + params.parameterName() + " must specify the PIN");
        }
    }

    @Override
    public Provider getProvider(KeyStoreBuilder params) {
        try {
            return new SigningServiceJcaProvider(new OpenPGPCardSigningService(params.keystore(), params.storepass(), params.certfile() != null ? getCertificateStore(params) : null));
        } catch (CardException e) {
            throw new IllegalStateException("Failed to initialize the OpenPGP card", e);
        }
    }
}
