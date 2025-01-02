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

import java.util.HashMap;
import java.util.Map;
import java.util.ServiceLoader;
import java.util.Set;

public class JsignKeyStoreDiscovery {
    private static Map<String, JsignKeyStore> keyStoresByType = new HashMap<>();

    static {
        Map<String, JsignKeyStore> keyStoresByType = new HashMap<>();
        for (JsignKeyStore keyStore : ServiceLoader.load(JsignKeyStore.class)) {
            if (keyStoresByType.put(keyStore.getType(), keyStore) != null) {
                throw new IllegalStateException("Duplicate key store type: " + keyStore.getType());
            }
        }
        JsignKeyStoreDiscovery.keyStoresByType = keyStoresByType;
    }

    private JsignKeyStoreDiscovery() {
    }

    public static JsignKeyStore getKeyStore(KeyStoreType type) {
        return keyStoresByType.get(type.name());
    }

    public static JsignKeyStore getKeyStore(String type) {
        return keyStoresByType.get(type);
    }

    public static Set<String> getKeyStoreTypes() {
        return keyStoresByType.keySet();
    }
}
