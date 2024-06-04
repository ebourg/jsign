/**
 * Copyright 2021 Emmanuel Bourg
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
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

import net.jsign.DigestAlgorithm;

/**
 * JCA Provider using a signing service.
 *
 * <p>Example:</p>
 * <pre>
 * Provider provider = new SigningServiceJcaProvider(new AzureKeyVaultSigningService(vault, token));
 * KeyStore keystore = KeyStore.getInstance("AZUREKEYVAULT", provider);
 * </pre>
 *
 * @since 4.0
 */
public class SigningServiceJcaProvider extends Provider {

    public SigningServiceJcaProvider(SigningService service) {
        super(service.getName(), 1.0, service.getName() + " signing service provider");

        AccessController.doPrivileged((PrivilegedAction<Object>) () -> {
            putService(new ProviderService(this, "KeyStore", service.getName().toUpperCase(), SigningServiceKeyStore.class.getName(), () -> new SigningServiceKeyStore(service)));

            for (String alg : new String[]{"RSA", "ECDSA"}) {
                for (DigestAlgorithm digest : DigestAlgorithm.values()) {
                    if (digest != DigestAlgorithm.MD5) {
                        String algorithm = digest.name() + "with" + alg;
                        putService(new ProviderService(this, "Signature", algorithm, SigningServiceSignature.class.getName(), () -> new SigningServiceSignature(algorithm)));
                    }
                }
            }
            return null;
        });
    }
}
