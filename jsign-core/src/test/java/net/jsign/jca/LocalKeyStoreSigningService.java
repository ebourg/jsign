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

import java.io.File;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.util.Collections;
import java.util.List;

import net.jsign.KeyStoreUtils;

/**
 * Signing service using a local KeyStore (for testing only).
 */
class LocalKeyStoreSigningService implements SigningService {

    private final String keypass;
    private final KeyStore keystore;

    public LocalKeyStoreSigningService(String keystoreFile, String storepass, String keypass) throws KeyStoreException {
        this.keypass = keypass;
        this.keystore = KeyStoreUtils.load(new File(keystoreFile), null, storepass, null);
    }

    @Override
    public String getName() {
        return "LocalKeyStore";
    }

    @Override
    public List<String> aliases() throws KeyStoreException {
        return Collections.list(keystore.aliases());
    }

    @Override
    public Certificate[] getCertificateChain(String alias) throws KeyStoreException {
        return keystore.getCertificateChain(alias);
    }

    @Override
    public SigningServicePrivateKey getPrivateKey(String alias, char[] password) throws UnrecoverableKeyException {
        PrivateKey privateKey;
        try {
            privateKey = (PrivateKey) keystore.getKey(alias, keypass != null ? keypass.toCharArray() : new char[0]);
        } catch (KeyStoreException | NoSuchAlgorithmException e) {
            throw (UnrecoverableKeyException) new UnrecoverableKeyException().initCause(e);
        }
        return new SigningServicePrivateKey(alias, privateKey.getAlgorithm());
    }

    @Override
    public byte[] sign(SigningServicePrivateKey privateKey, String algorithm, byte[] data) throws GeneralSecurityException {
        Signature signature = Signature.getInstance(algorithm);
        signature.initSign((PrivateKey) keystore.getKey(privateKey.getId(), keypass != null ? keypass.toCharArray() : new char[0]));
        signature.update(data);
        return signature.sign();
    }
}
