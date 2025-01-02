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
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Signature;

import org.junit.Assume;
import org.junit.Test;

import static net.jsign.KeyStoreType.YUBIKEY;
import static org.junit.Assert.*;

public class YubikeyTest {

    public static void assumeYubikey() {
        Assume.assumeTrue("libykcs11 isn't installed",
                new File(System.getenv("ProgramFiles") + "/Yubico/Yubico PIV Tool/bin/libykcs11.dll").exists()
             || new File("/usr/lib/x86_64-linux-gnu/libykcs11.so").exists());
        Assume.assumeTrue("No Yubikey detected", YubiKeyKeyStore.isPresent());
    }

    @Test
    public void testGetProvider() {
        assumeYubikey();
        Provider provider = JsignKeyStoreDiscovery.getKeyStore(YUBIKEY).getProvider(null);
        assertNotNull("provider", provider);
    }

    @Test
    public void testGetLibrary() {
        assumeYubikey();
        File library = YubiKeyKeyStore.getYkcs11Library();
        assertNotNull("native library", library);
        assertTrue("native library not found", library.exists());
    }

    @Test
    public void testAutoLogin() throws Exception {
        assumeYubikey();

        Provider provider = JsignKeyStoreDiscovery.getKeyStore(YUBIKEY).getProvider(null);
        KeyStore keystore = KeyStore.getInstance("PKCS11", provider);
        assertEquals("provider", provider, keystore.getProvider());
        keystore.load(() -> new KeyStore.PasswordProtection("123456".toCharArray()));

        String alias = keystore.aliases().nextElement();

        PrivateKey key = (PrivateKey) keystore.getKey(alias, "123456".toCharArray());

        // first signature
        Signature signature = Signature.getInstance("SHA256withRSA", provider);
        signature.initSign(key);
        signature.update("Hello World".getBytes());
        byte[] s1 = signature.sign();

        assertNotNull("signature null", s1);

        key = (PrivateKey) keystore.getKey(alias, "123456".toCharArray());

        // second signature
        signature = Signature.getInstance("SHA256withRSA", provider);
        signature.initSign(key);
        signature.update("Hello World".getBytes());
        byte[] s2 = signature.sign();

        assertArrayEquals("signature", s1, s2);
    }
}
