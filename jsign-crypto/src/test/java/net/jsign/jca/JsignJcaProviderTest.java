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

package net.jsign.jca;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;

import org.junit.Test;

import net.jsign.DigestAlgorithm;
import net.jsign.KeyStoreType;
import net.jsign.YubikeyTest;

import static org.junit.Assert.*;

public class JsignJcaProviderTest {

    @Test
    public void testServices() {
        JsignJcaProvider provider = new JsignJcaProvider();

        for (KeyStoreType type : KeyStoreType.values()) {
            assertNotNull("KeyStore " + type.name(), provider.getService("KeyStore", type.name()));
        }

        for (String alg : new String[]{"RSA", "ECDSA"}) {
            for (DigestAlgorithm digest : DigestAlgorithm.values()) {
                if (digest != DigestAlgorithm.MD5) {
                    String algorithm = digest.name() + "with" + alg;
                    assertNotNull("Signature " + algorithm, provider.getService("Signature", algorithm));
                }
            }
        }
    }

    @Test
    public void testKeyStoreSigningService() throws Exception {
        JsignJcaProvider provider = new JsignJcaProvider("https://cs-try.ssl.com");

        KeyStore keystore = KeyStore.getInstance("ESIGNER", provider);
        keystore.load(null, "esigner_demo|esignerDemo#1".toCharArray());
        String alias = keystore.aliases().nextElement();

        PrivateKey key = (PrivateKey) keystore.getKey(alias, "RDXYgV9qju+6/7GnMf1vCbKexXVJmUVr+86Wq/8aIGg=".toCharArray());
        assertNotNull("key not found", key);

        Signature signature = Signature.getInstance("SHA256withRSA", provider);
        signature.initSign(key);
        signature.update("Lorem ipsum dolor sit amet".getBytes());

        assertNotNull("Signature", signature.sign());
    }

    @Test
    public void testKeyStorePKCS11() throws Exception {
        YubikeyTest.assumeYubikey();

        JsignJcaProvider provider = new JsignJcaProvider();

        KeyStore keystore = KeyStore.getInstance("YUBIKEY", provider);
        keystore.load(null, "123456".toCharArray());
        String alias = keystore.aliases().nextElement();

        PrivateKey key = (PrivateKey) keystore.getKey(alias, null);
        assertNotNull("key not found", key);

        Signature signature = Signature.getInstance("SHA256withRSA", provider);
        signature.initSign(key);
        signature.update("Lorem ipsum dolor sit amet".getBytes());

        assertNotNull("Signature", signature.sign());
    }
}
