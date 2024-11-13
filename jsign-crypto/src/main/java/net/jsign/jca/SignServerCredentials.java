/**
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

package net.jsign.jca;

import java.security.KeyStore;

import net.jsign.KeyStoreBuilder;

/**
 * Credentials for the Keyfactor SignServer REST API.
 *
 * @since 7.0
 */
public class SignServerCredentials {

    public final String username;
    public final String password;
    public final KeyStore.Builder keystore;

    public SignServerCredentials(String username, String password, String keystore, String storepass) {
        this(username, password, keystore == null ? null : new KeyStoreBuilder().keystore(keystore).storepass(storepass).builder());
    }

    public SignServerCredentials(String username, String password, KeyStore.Builder keystore) {
        this.username = username;
        this.password = password;
        this.keystore = keystore;
    }
}
