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

import java.security.Provider;

import org.kohsuke.MetaInfServices;

@MetaInfServices(KeyStoreType.class)
public class NitrokeyKeyStoreType extends PKCS11KeyStoreType {

    @Override
    public String name() {
        return "NITROKEY";
    }

    @Override
    public Provider getProvider(KeyStoreBuilder params) {
        return OpenSC.getProvider(params.keystore() != null ? params.keystore() : "Nitrokey");
    }
}
