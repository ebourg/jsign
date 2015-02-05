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
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;

import junit.framework.TestCase;

/**
 * @author Emmanuel Bourg
 * @since 1.0
 */
public class PVKTest extends TestCase {

    private static final BigInteger PRIVATE_EXPONENT =
            new BigInteger("13788674422761232192109366695045739320662968796524533596546649277291656131659948065389630" +
                           "43863182892121656403583604586787882685822217065895911603567776131650015111114787128093270" +
                           "38747175970780043259305835482179875435536692028556840275049932216177725039464021845390956" +
                           "48749365951054152409123155429217112278873");

    public void testParseUnencrypted() throws Exception {
        PrivateKey key = PVK.parse(new File("src/test/resources/privatekey.pvk"), "password");
        assertNotNull(key);
        
        RSAPrivateKey rsakey = (RSAPrivateKey) key;
        assertEquals("private exponent", PRIVATE_EXPONENT, rsakey.getPrivateExponent());
    }

    public void testParseEncrypted() throws Exception {
        PrivateKey key = PVK.parse(new File("src/test/resources/privatekey-encrypted.pvk"), "password");
        assertNotNull(key);
        
        RSAPrivateKey rsakey = (RSAPrivateKey) key;
        assertEquals("private exponent", PRIVATE_EXPONENT, rsakey.getPrivateExponent());
    }

    public void testCompare() throws Exception {
        PrivateKey key1 = PVK.parse(new File("src/test/resources/privatekey.pvk"), "password");
        PrivateKey key2 = PVK.parse(new File("src/test/resources/privatekey-encrypted.pvk"), "password");
        
        assertEquals(key1, key2);
    }

    public void testInvalidFile() throws Exception {
        try {
            PVK.parse(new File("src/test/resources/keystore.jks"), null);
            fail("IllegalArgumentException expected");
        } catch (IllegalArgumentException e) {
            // expected
        }
    }
}
