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

import net.jsign.jca.PIVCardSigningService;
import net.jsign.jca.SigningServiceJcaProvider;
import org.kohsuke.MetaInfServices;

import javax.smartcardio.CardException;
import java.security.Provider;

import static net.jsign.JsignKeyStore.getCertificateStore;

/**
 * PIV card. PIV cards contain up to 24 private keys and certificates. The alias to select the key is either,
 * <code>AUTHENTICATION</code>, <code>SIGNATURE</code>, <code>KEY_MANAGEMENT</code>, <code>CARD_AUTHENTICATION</code>,
 * or <code>RETIRED&lt;1-20&gt;</code>. Slot numbers are also accepted (for example <code>9c</code> for the digital
 * signature key). If multiple devices are connected, the keystore parameter can be used to specify the name
 * of the one to use. This keystore type doesn't require any external library to be installed.
 */
@MetaInfServices(JsignKeyStore.class)
public class PivKeyStore extends AbstractJsignKeyStore {
    @Override
    public String getType() {
        return "PIV";
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
            return new SigningServiceJcaProvider(new PIVCardSigningService(params.keystore(), params.storepass(), params.certfile() != null ? getCertificateStore(params) : null));
        } catch (CardException e) {
            throw new IllegalStateException("Failed to initialize the PIV card", e);
        }
    }
}
