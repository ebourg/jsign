/*
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
import java.security.Provider;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.junit.Assume;
import org.junit.Test;

import static org.junit.Assert.*;

public class SafeNetETokenTest {

    private void assumeSafeNetEToken() {
        Assume.assumeTrue("SafeNet Authentication Client isn't installed",
                new File(System.getenv("windir") + "/system32/eTPKCS11.dll").exists()
             || new File("/usr/lib/pkcs11/libeToken.so").exists());
    }

    @Test
    public void testGetProvider() {
        assumeSafeNetEToken();
        try {
            Provider provider = SafeNetEToken.getProvider();
            assertNotNull("provider", provider);
        } catch (RuntimeException e) {
            assertEquals("message", "No PKCS11 token found", ExceptionUtils.getRootCause(e).getMessage());
        }
    }

    @Test
    public void testGetLibrary() {
        assumeSafeNetEToken();
        File library = SafeNetEToken.getPKCS11Library();
        assertNotNull("native library", library);
        assertTrue("native library not found", library.exists());
    }
}
