/**
 * Copyright 2012 Emmanuel Bourg
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

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;

import net.jsign.pe.PEFile;

/**
 * Sign a portable executable file. Timestamping is enabled by default
 * and relies on the Comodo server (http://timestamp.comodoca.com/authenticode).
 * 
 * @see <a href="http://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/Authenticode_PE.docx">Windows Authenticode Portable Executable Signature Format</a>
 * @see <a href="http://msdn.microsoft.com/en-us/library/windows/desktop/bb931395%28v=vs.85%29.aspx?ppud=4">Time Stamping Authenticode Signatures</a>
 * 
 * @author Emmanuel Bourg
 * @since 1.0
 * @deprecated Use {@link AuthenticodeSigner} instead
 */
@Deprecated
public class PESigner extends AuthenticodeSigner<PESigner> {

    /**
     * Create a PESigner with the specified certificate chain and private key.
     *
     * @param chain       the certificate chain. The first certificate is the signing certificate
     * @param privateKey  the private key
     * @throws IllegalArgumentException if the chain is empty
     */
    public PESigner(Certificate[] chain, PrivateKey privateKey) {
        super(chain, privateKey);
    }

    /**
     * Create a PESigner with a certificate chain and private key from the specified keystore.
     *
     * @param keystore the keystore holding the certificate and the private key
     * @param alias    the alias of the certificate in the keystore
     * @param password the password to get the private key
     * @throws KeyStoreException if the keystore has not been initialized (loaded).
     * @throws NoSuchAlgorithmException if the algorithm for recovering the key cannot be found
     * @throws UnrecoverableKeyException if the key cannot be recovered (e.g., the given password is wrong).
     */
    public PESigner(KeyStore keystore, String alias, String password) throws NoSuchAlgorithmException, KeyStoreException, UnrecoverableKeyException {
        super(keystore, alias, password);
    }

    /**
     * Set the URL of the timestamping authority. Both RFC 3161 (as used for jar signing)
     * and Authenticode timestamping services are supported.
     * 
     * @param url the URL of the timestamping authority
     * @return the current signer
     * @deprecated Use {@link #withTimestampingAuthority(String)} instead
     */
    public PESigner withTimestampingAutority(String url) {
        return withTimestampingAuthority(url);
    }

    /**
     * Set the URLs of the timestamping authorities. Both RFC 3161 (as used for jar signing)
     * and Authenticode timestamping services are supported.
     *
     * @param urls the URLs of the timestamping authorities
     * @return the current signer
     * @since 2.0
     * @deprecated Use {@link #withTimestampingAuthority(String...)} instead
     */
    public PESigner withTimestampingAutority(String... urls) {
        return withTimestampingAuthority(urls);
    }

    /**
     * Sign the specified executable file.
     *
     * @param file the file to sign
     * @throws Exception if signing fails
     */
    public void sign(PEFile file) throws Exception {
        super.sign(file);
    }
}
