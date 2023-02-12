/**
 * Copyright 2023 Emmanuel Bourg
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.jsign;

import java.io.File;
import java.security.Provider;

import org.junit.Assume;
import org.junit.Test;

import static org.junit.Assert.*;

public class OpenSCTest {

    private void assumeOpenSC() {
        Assume.assumeTrue("libykcs11 isn't installed",
                new File(System.getenv("ProgramFiles") + "/OpenSC Project/OpenSC/pkcs11/opensc-pkcs11.dll").exists()
             || new File("/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so").exists());
    }

    @Test
    public void testGetProvider() {
        assumeOpenSC();
        try {
            Provider provider = OpenSC.getProvider(null);
            assertNotNull(provider);
        } catch (RuntimeException e) {
            assertEquals("No PKCS11 token found", e.getCause().getMessage());
        }
    }

    @Test
    public void testGetLibrary() {
        assumeOpenSC();
        File library = OpenSC.getOpenSCLibrary();
        assertNotNull(library);
        assertTrue(library.exists());
    }
}
