/*
 * Copyright 2024 Björn Kautler
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

import org.kohsuke.MetaInfServices;

import java.security.Provider;

/**
 * Nitrokey HSM. This keystore requires the installation of <a href="https://github.com/OpenSC/OpenSC">OpenSC</a>.
 * Other Nitrokeys based on the OpenPGP card standard are also supported with this storetype, but an X.509
 * certificate must be imported into the Nitrokey (using the gnupg writecert command). Keys without certificates
 * are ignored. Otherwise, the {@link OpenPGPKeyStore} type should be used.
 */
@MetaInfServices(JsignKeyStore.class)
public class NitroKeyKeyStore extends Pkcs11KeyStore {
    @Override
    public String getType() {
        return "NITROKEY";
    }

    @Override
    public Provider getProvider(KeyStoreBuilder params) {
        return OpenSCKeyStore.getProvider(params.keystore() != null ? params.keystore() : "Nitrokey");
    }
}
