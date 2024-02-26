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
import java.security.Provider;
import java.util.Set;

import org.kohsuke.MetaInfServices;

@MetaInfServices(KeyStoreType.class)
public class YubikeyKeyStoreType extends PKCS11KeyStoreType {

    @Override
    public String name() {
        return "YUBIKEY";
    }

    @Override
    public Provider getProvider(KeyStoreBuilder params) {
        return YubiKey.getProvider();
    }

    @Override
    public Set<String> getAliases(KeyStore keystore) throws KeyStoreException {
        Set<String> aliases = super.getAliases(keystore);
        // the attestation certificate is never used for signing
        aliases.remove("X.509 Certificate for PIV Attestation");
        return aliases;
    }
}
