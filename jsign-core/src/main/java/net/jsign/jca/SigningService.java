/**
 * Copyright 2021 Emmanuel Bourg
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

package net.jsign.jca;

import java.security.GeneralSecurityException;
import java.security.KeyStoreException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.util.List;

/**
 * Interface to a signing service.
 *
 * @since 4.0
 */
public interface SigningService {

    /**
     * Returns the name of the service.
     */
    String getName();

    /**
     * Returns the certificate aliases available.
     */
    List<String> aliases() throws KeyStoreException;

    /**
     * Returns the certificate chain for the alias specified.
     *
     * @param alias the name of the certificate
     */
    Certificate[] getCertificateChain(String alias) throws KeyStoreException;

    /**
     * Returns the private key for the certificate alias specified.
     *
     * @param alias the name of the certificate
     * @param password the secret required to access the key
     */
    SigningServicePrivateKey getPrivateKey(String alias, char[] password) throws UnrecoverableKeyException;

    /**
     * Returns the private key for the certificate alias specified.
     *
     * @param alias the name of the certificate
     */
    @Deprecated
    default SigningServicePrivateKey getPrivateKey(String alias) throws UnrecoverableKeyException {
        return getPrivateKey(alias, null);
    }

    /**
     * Sign the data with the private key specified.
     *
     * @param privateKey the private key
     * @param algorithm  the signing algorithm (for example SHA256withRSA)
     * @param data       the data to be signed
     */
    byte[] sign(SigningServicePrivateKey privateKey, String algorithm, byte[] data) throws GeneralSecurityException;
}
