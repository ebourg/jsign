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

import java.util.Arrays;
import java.util.List;

import org.junit.Test;

import static org.junit.Assert.*;

public class KeyStoreTypeTest {

    @Test
    public void testValueOf() {
        assertEquals(KeyStoreType.JCEKS, KeyStoreType.valueOf("JCEKS"));
        assertEquals(KeyStoreType.OPENSC, KeyStoreType.valueOf("OPENSC"));
        assertEquals(KeyStoreType.OPENPGP, KeyStoreType.valueOf("OPENPGP"));
        assertEquals(KeyStoreType.DIGICERTONE, KeyStoreType.valueOf("DIGICERTONE"));
    }

    @Test
    public void testValues() {
        List<KeyStoreType> values = Arrays.asList(KeyStoreType.values());
        assertTrue(values.contains(KeyStoreType.NONE));
        assertTrue(values.contains(KeyStoreType.PKCS12));
        assertTrue(values.contains(KeyStoreType.JKS));
        assertTrue(values.contains(KeyStoreType.PKCS11));
        assertTrue(values.contains(KeyStoreType.PIV));
        assertTrue(values.contains(KeyStoreType.AWS));
    }
}
