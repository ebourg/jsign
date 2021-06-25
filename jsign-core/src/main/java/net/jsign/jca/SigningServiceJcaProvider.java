/**
 * Copyright 2021 Emmanuel Bourg
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.jsign.jca;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.util.Collections;

import net.jsign.DigestAlgorithm;

/**
 * JCA Provider using a signing service.
 *
 * @since 4.0
 */
public class SigningServiceJcaProvider extends Provider {

    private final SigningService service;

    public SigningServiceJcaProvider(SigningService service) {
        super(service.getName(), 1.0, service.getName() + " signing service provider");
        this.service = service;

        AccessController.doPrivileged((PrivilegedAction<Object>) () -> {
            putService(new KeyStoreProviderService());
            for (String alg : new String[]{"RSA", "ECDSA"}) {
                for (DigestAlgorithm digest : DigestAlgorithm.values()) {
                    if (digest != DigestAlgorithm.MD5) {
                        putService(new SignatureProviderService(digest.name() + "with" + alg));
                    }
                }
            }
            return null;
        });
    }

    private class KeyStoreProviderService extends Service {
        public KeyStoreProviderService() {
            super(SigningServiceJcaProvider.this, "KeyStore", service.getName().toUpperCase(), SigningServiceKeyStore.class.getName(), Collections.emptyList(), null);
        }

        @Override
        public Object newInstance(Object constructorParameter) {
            return new SigningServiceKeyStore(service);
        }
    }

    private class SignatureProviderService extends Service {

        private final String signingAlgorithm;

        public SignatureProviderService(String signingAlgorithm) {
            super(SigningServiceJcaProvider.this, "Signature", signingAlgorithm, SigningServiceSignature.class.getName(), Collections.emptyList(), Collections.emptyMap());
            this.signingAlgorithm = signingAlgorithm;
        }

        @Override
        public Object newInstance(Object constructorParameter) {
            return new SigningServiceSignature(service, signingAlgorithm);
        }
    }
}
