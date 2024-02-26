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
import javax.smartcardio.CardException;

import org.kohsuke.MetaInfServices;

import net.jsign.jca.PIVCardSigningService;
import net.jsign.jca.SigningServiceJcaProvider;

@MetaInfServices(KeyStoreType.class)
public class PIVKeyStoreType extends AbstractKeyStoreType {

    @Override
    public String name() {
        return "PIV";
    }

    @Override
    public void validate(KeyStoreBuilder params) {
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
