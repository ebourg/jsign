/**
 * Copyright 2017 Emmanuel Bourg
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
import java.io.FileWriter;
import java.math.BigInteger;
import java.security.KeyException;
import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;

import org.junit.Test;

import static org.junit.Assert.*;

public class PrivateKeyUtilsTest {

    private static final BigInteger PRIVATE_EXPONENT =
            new BigInteger("13788674422761232192109366695045739320662968796524533596546649277291656131659948065389630" +
                           "43863182892121656403583604586787882685822217065895911603567776131650015111114787128093270" +
                           "38747175970780043259305835482179875435536692028556840275049932216177725039464021845390956" +
                           "48749365951054152409123155429217112278873");

    @Test
    public void testLoadPKCS8PEM() throws Exception {
        testLoadPEM(new File("target/test-classes/keystores/privatekey.pkcs8.pem"), null);
    }

    @Test
    public void testLoadEncryptedPKCS8PEM() throws Exception {
        testLoadPEM(new File("target/test-classes/keystores/privatekey-encrypted.pkcs8.pem"), "password");
    }

    @Test
    public void testLoadPKCS1PEM() throws Exception {
        testLoadPEM(new File("target/test-classes/keystores/privatekey.pkcs1.pem"), null);
    }

    @Test
    public void testLoadEncryptedPKCS1PEM() throws Exception {
        testLoadPEM(new File("target/test-classes/keystores/privatekey-encrypted.pkcs1.pem"), "password");
    }

    private void testLoadPEM(File file, String password) throws Exception {
        PrivateKey key = PrivateKeyUtils.load(file, password);
        assertNotNull("null key", key);
        assertEquals("algorithm", "RSA", key.getAlgorithm());
        
        RSAPrivateKey rsakey = (RSAPrivateKey) key;
        assertEquals("private exponent", PRIVATE_EXPONENT, rsakey.getPrivateExponent());
    }

    @Test
    public void testLoadWrongPEMObject() {
        try {
            PrivateKeyUtils.load(new File("target/test-classes/keystores/jsign-test-certificate.pem"), null);
            fail("No exception thrown");
        } catch (KeyException e) {
            Throwable cause = e.getCause();
            assertEquals("exception message", "Unsupported PEM object: X509CertificateHolder", cause.getMessage());
        }
    }

    @Test
    public void testLoadEmptyPEM() throws Exception {
        File file = new File("target/test-classes/keystores/empty.pem");
        FileWriter writer = new FileWriter(file);
        writer.write("");
        writer.close();

        try {
            PrivateKeyUtils.load(file, null);
            fail("No exception thrown");
        } catch (KeyException e) {
            Throwable cause = e.getCause();
            assertTrue(cause.getMessage().startsWith("No key found in"));
        }
    }

    @Test
    public void testLoadECKey() throws Exception {
        PrivateKey key = PrivateKeyUtils.load(new File("target/test-classes/keystores/privatekey-ec-p384.pkcs1.pem"), null);
        assertNotNull("null key", key);
        assertEquals("algorithm", "ECDSA", key.getAlgorithm());
        ECPrivateKey eckey = (ECPrivateKey) key;
        assertEquals(new BigInteger("20257491648229957920568032976799761096297361118969955946704763806669063295695225962636427229581436831963662222302926"), eckey.getS());
    }
}
