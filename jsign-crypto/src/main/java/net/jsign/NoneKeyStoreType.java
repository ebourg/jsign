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

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.Certificate;

import org.kohsuke.MetaInfServices;

@MetaInfServices(KeyStoreType.class)
public class NoneKeyStoreType extends AbstractKeyStoreType {

    @Override
    public String name() {
        return "NONE";
    }

    @Override
    public void validate(KeyStoreBuilder params) {
        if (params.keyfile() == null) {
            throw new IllegalArgumentException("keyfile " + params.parameterName() + " must be set");
        }
        if (!params.keyfile().exists()) {
            throw new IllegalArgumentException("The keyfile " + params.keyfile() + " couldn't be found");
        }
        if (params.certfile() == null) {
            throw new IllegalArgumentException("certfile " + params.parameterName() + " must be set");
        }
        if (!params.certfile().exists()) {
            throw new IllegalArgumentException("The certfile " + params.certfile() + " couldn't be found");
        }
    }

    @Override
    public KeyStore getKeystore(KeyStoreBuilder params, Provider provider) throws KeyStoreException {
        // load the certificate chain
        Certificate[] chain;
        try {
            chain = CertificateUtils.loadCertificateChain(params.certfile());
        } catch (Exception e) {
            throw new KeyStoreException("Failed to load the certificate from " + params.certfile(), e);
        }

        // load the private key
        PrivateKey privateKey;
        try {
            privateKey = PrivateKeyUtils.load(params.keyfile(), params.keypass() != null ? params.keypass() : params.storepass());
        } catch (Exception e) {
            throw new KeyStoreException("Failed to load the private key from " + params.keyfile(), e);
        }

        // build the in-memory keystore
        KeyStore ks = KeyStore.getInstance("JKS");
        try {
            ks.load(null, null);
            String keypass = params.keypass();
            ks.setKeyEntry("jsign", privateKey, keypass != null ? keypass.toCharArray() : new char[0], chain);
        } catch (Exception e) {
            throw new KeyStoreException(e);
        }

        return ks;
    }
}
