/**
 * Copyright 2012 Emmanuel Bourg
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
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;

import org.junit.Test;

import static org.junit.Assert.*;

public class PVKTest {

    private static final BigInteger PRIVATE_EXPONENT =
            new BigInteger("13788674422761232192109366695045739320662968796524533596546649277291656131659948065389630" +
                           "43863182892121656403583604586787882685822217065895911603567776131650015111114787128093270" +
                           "38747175970780043259305835482179875435536692028556840275049932216177725039464021845390956" +
                           "48749365951054152409123155429217112278873");

    private static final BigInteger MODULUS =
            new BigInteger("10827562372927185168634933681922029928807680158373213016018185402418682816925449513077404" +
                           "86528413817409261870616567143593547418892051759497008851701669594509162542812252927073053" +
                           "63776062597224618555740476093967060229674515611975718626261740683864624806740655247266908" +
                           "985568698016685062096774422670704602453741");

    @Test
    public void testParseUnencrypted() throws Exception {
        testParse("src/test/resources/keystores/privatekey.pvk");
    }

    @Test
    public void testParseEncryptedWeak() throws Exception {
        testParse("src/test/resources/keystores/privatekey-encrypted.pvk");
    }

    @Test
    public void testParseEncryptedStrong() throws Exception {
        testParse("src/test/resources/keystores/privatekey-encrypted-strong.pvk");
    }

    private void testParse(String filename) throws Exception {
        PrivateKey key = PVK.parse(new File(filename), "password");
        assertNotNull(key);
        
        RSAPrivateKey rsakey = (RSAPrivateKey) key;
        assertEquals("private exponent", PRIVATE_EXPONENT, rsakey.getPrivateExponent());
        assertEquals("modulus", MODULUS, rsakey.getModulus());
    }

    @Test
    public void testCompare() throws Exception {
        PrivateKey key1 = PVK.parse(new File("src/test/resources/keystores/privatekey.pvk"), "password");
        PrivateKey key2 = PVK.parse(new File("src/test/resources/keystores/privatekey-encrypted.pvk"), "password");
        
        assertEquals(key1, key2);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testInvalidFile() throws Exception {
        PVK.parse(new File("src/test/resources/keystores/keystore.jks"), null);
    }

    @Test
    public void testInvalidPassword() throws Exception {
        try {
            PVK.parse(new File("src/test/resources/keystores/privatekey-encrypted.pvk"), "secret");
            fail("IllegalArgumentException expected");
        } catch (IllegalArgumentException e) {
            assertEquals("exception message", "Unable to decrypt the PVK key, please verify the password", e.getMessage());
        }
    }

    @Test
    public void testMissingPassword() throws Exception {
        try {
            PVK.parse(new File("src/test/resources/keystores/privatekey-encrypted.pvk"), null);
            fail("IllegalArgumentException expected");
        } catch (IllegalArgumentException e) {
            assertEquals("exception message", "Unable to decrypt the PVK key, please verify the password", e.getMessage());
        }
    }
}
