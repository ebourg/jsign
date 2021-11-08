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

import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.Vector;

class SigningServiceKeyStore extends KeyStoreSpi {
    
    private final SigningService service;

    public SigningServiceKeyStore(SigningService service) {
        this.service = service;
    }

    @Override
    public Key engineGetKey(String alias, char[] password) throws UnrecoverableKeyException {
        return service.getPrivateKey(alias, password);
    }

    @Override
    public Certificate[] engineGetCertificateChain(String alias) {
        try {
            return service.getCertificateChain(alias);
        } catch (KeyStoreException e) {
            return null;
        }
    }

    @Override
    public Certificate engineGetCertificate(String alias) {
        throw new UnsupportedOperationException();
    }

    @Override
    public Date engineGetCreationDate(String alias) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void engineSetKeyEntry(String alias, Key key, char[] password, Certificate[] chain) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void engineSetKeyEntry(String alias, byte[] key, Certificate[] chain) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void engineSetCertificateEntry(String alias, Certificate cert) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void engineDeleteEntry(String alias) {
        throw new UnsupportedOperationException();
    }

    @Override
    public Enumeration<String> engineAliases() {
        try {
            return new Vector<>(service.aliases()).elements();
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public boolean engineContainsAlias(String alias) {
        Enumeration<String> aliases = engineAliases();
        while (aliases.hasMoreElements()) {
            if (aliases.nextElement().equals(alias)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public int engineSize() {
        return Collections.list(engineAliases()).size();
    }

    @Override
    public boolean engineIsKeyEntry(String alias) {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean engineIsCertificateEntry(String alias) {
        throw new UnsupportedOperationException();
    }

    @Override
    public String engineGetCertificateAlias(Certificate cert) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void engineStore(OutputStream stream, char[] password) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void engineLoad(InputStream stream, char[] password) {
    }
}
