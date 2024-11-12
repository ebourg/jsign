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
            new BigInteger("19817169968742658351655981881520728567515742675458028238722873450752489545290027368716540" +
                           "85097631066624963034561175250684606477209898571693535966680219017373301210696301524715693" +
                           "32813430171550590717633111906205004670354975513186220085378522264569873656534297526647600" +
                           "67210063630643422050150940116280163778449179706229972233451580723669324903567379792001184" +
                           "91356375507388894454096016139651604806035749246665341527152435463187733601651656903848705" +
                           "65286430323121648102905511694715343290174710008776316150944558295836976757991350461460249" +
                           "74312281235327661476877170425283316600383477434537031658944220883861196634055190385");

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
        Exception e = assertThrows(KeyException.class, () -> PrivateKeyUtils.load(new File("target/test-classes/keystores/jsign-test-certificate.pem"), null));
        assertEquals("message", "Unsupported PEM object: X509CertificateHolder", e.getCause().getMessage());
    }

    @Test
    public void testLoadEmptyPEM() throws Exception {
        File file = new File("target/test-classes/keystores/empty.pem");
        FileWriter writer = new FileWriter(file);
        writer.write("");
        writer.close();

        Exception e = assertThrows(KeyException.class, () -> PrivateKeyUtils.load(file, null));
        assertTrue(e.getCause().getMessage().startsWith("No key found in"));
    }

    @Test
    public void testLoadECKey() throws Exception {
        PrivateKey key = PrivateKeyUtils.load(new File("target/test-classes/keystores/privatekey-ec-p384.pkcs1.pem"), null);
        assertNotNull("null key", key);
        assertEquals("algorithm", "ECDSA", key.getAlgorithm());
        ECPrivateKey eckey = (ECPrivateKey) key;
        assertEquals("S value", new BigInteger("20257491648229957920568032976799761096297361118969955946704763806669063295695225962636427229581436831963662222302926"), eckey.getS());
    }
}
