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
import java.security.Provider;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;

import net.jsign.pe.PEFile;
import net.jsign.timestamp.Timestamper;
import net.jsign.timestamp.TimestampingMode;

/**
 * Sign a portable executable file. Timestamping is enabled by default
 * and relies on the Sectigo server (http://timestamp.sectigo.com).
 * 
 * @see <a href="https://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/Authenticode_PE.docx">Windows Authenticode Portable Executable Signature Format</a>
 * @see <a href="https://docs.microsoft.com/en-us/windows/win32/seccrypto/time-stamping-authenticode-signatures">Time Stamping Authenticode Signatures</a>
 * 
 * @author Emmanuel Bourg
 * @since 1.0
 * @deprecated Use {@link AuthenticodeSigner} instead
 */
@Deprecated
public class PESigner extends AuthenticodeSigner {

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
     * Set the program name embedded in the signature.
     * 
     * @param programName the program name
     * @return the current signer
     */
    public PESigner withProgramName(String programName) {
        return (PESigner) super.withProgramName(programName);
    }

    /**
     * Set the program URL embedded in the signature.
     * 
     * @param programURL the program URL
     * @return the current signer
     */
    public PESigner withProgramURL(String programURL) {
        return (PESigner) super.withProgramURL(programURL);
    }

    /**
     * Enable or disable the replacement of the previous signatures (disabled by default).
     * 
     * @param replace <code>true</code> if the new signature should replace the existing ones, <code>false</code> to append it
     * @return the current signer
     * @since 2.0
     */
    public PESigner withSignaturesReplaced(boolean replace) {
        return (PESigner) super.withSignaturesReplaced(replace);
    }

    /**
     * Enable or disable the timestamping (enabled by default).
     * 
     * @param timestamping <code>true</code> to enable timestamping, <code>false</code> to disable it
     * @return the current signer
     */
    public PESigner withTimestamping(boolean timestamping) {
        return (PESigner) super.withTimestamping(timestamping);
    }

    /**
     * RFC3161 or Authenticode (Authenticode by default).
     * 
     * @param tsmode the timestamping mode
     * @return the current signer
     * @since 1.3
     */
    public PESigner withTimestampingMode(TimestampingMode tsmode) {
        return (PESigner) super.withTimestampingMode(tsmode);
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
     * Set the URL of the timestamping authority. Both RFC 3161 (as used for jar signing)
     * and Authenticode timestamping services are supported.
     * 
     * @param url the URL of the timestamping authority
     * @return the current signer
     * @since 2.1
     */
    public PESigner withTimestampingAuthority(String url) {
        return (PESigner) super.withTimestampingAuthority(url);
    }

    /**
     * Set the URLs of the timestamping authorities. Both RFC 3161 (as used for jar signing)
     * and Authenticode timestamping services are supported.
     * 
     * @param urls the URLs of the timestamping authorities
     * @return the current signer
     * @since 2.1
     */
    public PESigner withTimestampingAuthority(String... urls) {
        return (PESigner) super.withTimestampingAuthority(urls);
    }

    /**
     * Set the Timestamper implementation.
     * 
     * @param timestamper the timestamper implementation to use
     * @return the current signer
     */
    public PESigner withTimestamper(Timestamper timestamper) {
        return (PESigner) super.withTimestamper(timestamper);
    }

    /**
     * Set the number of retries for timestamping.
     * 
     * @param timestampingRetries the number of retries
     * @return the current signer
     */
    public PESigner withTimestampingRetries(int timestampingRetries) {
        return (PESigner) super.withTimestampingRetries(timestampingRetries);
    }

    /**
     * Set the number of seconds to wait between timestamping retries.
     * 
     * @param timestampingRetryWait the wait time between retries (in seconds)
     * @return the current signer
     */
    public PESigner withTimestampingRetryWait(int timestampingRetryWait) {
        return (PESigner) super.withTimestampingRetryWait(timestampingRetryWait);
    }

    /**
     * Set the digest algorithm to use (SHA-256 by default)
     * 
     * @param algorithm the digest algorithm
     * @return the current signer
     */
    public PESigner withDigestAlgorithm(DigestAlgorithm algorithm) {
        return (PESigner) super.withDigestAlgorithm(algorithm);
    }

    /**
     * Explicitly sets the signature algorithm to use.
     * 
     * @param signatureAlgorithm the signature algorithm
     * @return the current signer
     * @since 2.0
     */
    public PESigner withSignatureAlgorithm(String signatureAlgorithm) {
        return (PESigner) super.withSignatureAlgorithm(signatureAlgorithm);
    }

    /**
     * Explicitly sets the signature algorithm and provider to use.
     * 
     * @param signatureAlgorithm the signature algorithm
     * @param signatureProvider the security provider for the specified algorithm
     * @return the current signer
     * @since 2.0
     */
    public PESigner withSignatureAlgorithm(String signatureAlgorithm, String signatureProvider) {
        return withSignatureAlgorithm(signatureAlgorithm, Security.getProvider(signatureProvider));
    }

    /**
     * Explicitly sets the signature algorithm and provider to use.
     * 
     * @param signatureAlgorithm the signature algorithm
     * @param signatureProvider the security provider for the specified algorithm
     * @return the current signer
     * @since 2.0
     */
    public PESigner withSignatureAlgorithm(String signatureAlgorithm, Provider signatureProvider) {
        return (PESigner) super.withSignatureAlgorithm(signatureAlgorithm, signatureProvider);
    }

    /**
     * Set the signature provider to use.
     * 
     * @param signatureProvider the security provider for the signature algorithm
     * @return the current signer
     * @since 2.0
     */
    public PESigner withSignatureProvider(Provider signatureProvider) {
        return (PESigner) super.withSignatureProvider(signatureProvider);
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
