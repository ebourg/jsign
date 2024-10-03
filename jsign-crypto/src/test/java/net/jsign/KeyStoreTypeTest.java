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

package net.jsign;

import java.io.File;

import org.apache.commons.io.FileUtils;
import org.junit.Test;

import static net.jsign.KeyStoreType.*;
import static org.junit.Assert.*;

public class KeyStoreTypeTest {

    @Test
    public void testGetType() throws Exception {
        assertEquals(PKCS12, KeyStoreType.of(new File("keystore.p12")));
        assertEquals(PKCS12, KeyStoreType.of(new File("keystore.pfx")));
        assertEquals(JCEKS, KeyStoreType.of(new File("keystore.jceks")));
        assertEquals(JKS, KeyStoreType.of(new File("keystore.jks")));
        assertNull(KeyStoreType.of(new File("keystore.unknown")));
    }

    @Test
    public void testGetTypePKCS12FromHeader() throws Exception {
        File source = new File("target/test-classes/keystores/keystore.p12");
        File target = new File("target/test-classes/keystores/keystore.p12.ext");
        FileUtils.copyFile(source, target);

        assertEquals(PKCS12, KeyStoreType.of(target));
    }

    @Test
    public void testGetTypeJCEKSFromHeader() throws Exception {
        File source = new File("target/test-classes/keystores/keystore.jceks");
        File target = new File("target/test-classes/keystores/keystore.jceks.ext");
        FileUtils.copyFile(source, target);

        assertEquals(JCEKS, KeyStoreType.of(target));
    }

    @Test
    public void testGetTypeJKSFromHeader() throws Exception {
        File source = new File("target/test-classes/keystores/keystore.jks");
        File target = new File("target/test-classes/keystores/keystore.jks.ext");
        FileUtils.copyFile(source, target);

        assertEquals(JKS, KeyStoreType.of(target));
    }

    @Test
    public void testGetTypeUnknown() throws Exception {
        assertNull(KeyStoreType.of(new File("target/test-classes/keystores/jsign-root-ca.pem")));
    }
}
