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
import java.security.Provider;

import org.junit.Assume;
import org.junit.Test;

import static org.junit.Assert.*;

public class YubikeyTest {

    public static void assumeYubikey() {
        Assume.assumeTrue("libykcs11 isn't installed",
                new File(System.getenv("ProgramFiles") + "/Yubico/Yubico PIV Tool/bin/libykcs11.dll").exists()
             || new File("/usr/lib/x86_64-linux-gnu/libykcs11.so").exists());
        Assume.assumeTrue("No Yubikey detected", YubiKey.isPresent());
    }

    @Test
    public void testGetProvider() {
        assumeYubikey();
        Provider provider = YubiKey.getProvider();
        assertNotNull("provider", provider);
    }

    @Test
    public void testGetLibrary() {
        assumeYubikey();
        File library = YubiKey.getYkcs11Library();
        assertNotNull("native library", library);
        assertTrue("native library not found", library.exists());
    }
}
