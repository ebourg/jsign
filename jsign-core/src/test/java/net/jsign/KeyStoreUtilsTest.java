/**
 * Copyright 2023 Emmanuel Bourg
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

import java.io.File;
import java.security.KeyStore;

import org.junit.Test;

import static org.junit.Assert.*;

public class KeyStoreUtilsTest {

    @Test
    public void testLoadPKCS12() throws Exception {
        KeyStore keystore = KeyStoreUtils.load(new File("target/test-classes/keystores/keystore.p12"), "PKCS12", "password", null);
        assertNotNull("keystore", keystore);
    }

    @Test
    public void testLoadJKS() throws Exception {
        KeyStore keystore = KeyStoreUtils.load("target/test-classes/keystores/keystore.jks", null, "password", null);
        assertNotNull("keystore", keystore);
    }
}
