/*
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

import java.security.Key;
import java.security.KeyStoreException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.util.Enumeration;
import java.util.Vector;

class SigningServiceKeyStore extends AbstractKeyStoreSpi {
    
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
        Certificate[] chain = null;
        try {
            chain = service.getCertificateChain(alias);
        } catch (KeyStoreException e) {
            rethrow(e);
        }
        return chain;
    }

    @Override
    public Enumeration<String> engineAliases() {
        Enumeration<String> aliases = null;
        try {
            aliases = new Vector<>(service.aliases()).elements();
        } catch (KeyStoreException e) {
            rethrow(e);
        }
        return aliases;
    }

    private static <T extends Throwable> void rethrow(Throwable t) throws T {
        throw (T) t;
    }
}
