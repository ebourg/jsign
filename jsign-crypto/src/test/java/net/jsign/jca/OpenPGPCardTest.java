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

package net.jsign.jca;

import java.io.File;
import java.security.PrivateKey;
import java.util.Set;
import javax.crypto.Cipher;
import javax.smartcardio.CardException;

import org.apache.commons.codec.binary.Hex;
import org.junit.Test;

import net.jsign.PrivateKeyUtils;

import static org.junit.Assert.*;
import static org.junit.Assume.*;

public class OpenPGPCardTest {

    public static void assumeCardPresent() throws Exception {
        try {
            assumeTrue("OpenPGP card not found", SmartCard.getTerminal("Nitrokey") != null);
        } catch (CardException e) {
            assumeNoException("OpenPGP card not found", e);
        }
    }

    @Test
    public void testGetCard() throws Exception {
        assumeCardPresent();

        assertNotNull("card not found", OpenPGPCard.getCard());
    }

    @Test
    public void testSignWithSignatureKey() throws Exception {
        testSign(OpenPGPCard.Key.SIGNATURE);
    }

    @Test
    public void testSignWithAuthenticationKey() throws Exception {
        testSign(OpenPGPCard.Key.AUTHENTICATION);
    }

    @Test
    public void testSignWithEncryptionKey() throws Exception {
        testSign(OpenPGPCard.Key.ENCRYPTION);
    }

    public void testSign(OpenPGPCard.Key key) throws Exception {
        assumeCardPresent();

        String message = "Hello OpenPGP card";

        OpenPGPCard pgpcard = OpenPGPCard.getCard();
        assertNotNull("card not found", pgpcard);
        pgpcard.verify("123456");

        if (key == OpenPGPCard.Key.ENCRYPTION) {
            assumeTrue("OpenPGP card version 3+ required", pgpcard.getVersion() > 3);
        }

        byte[] result = pgpcard.sign(key, message.getBytes());

        assertNotNull("result", result);
        assertEquals("result length (bits)", 2048, result.length * 8);

        File privateKeyFile = new File("target/test-classes/keystores/privatekey.pkcs1.pem");
        PrivateKey privateKey = PrivateKeyUtils.load(privateKeyFile, null);

        // encrypt the message with the private key
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, privateKey);
        encryptCipher.update(message.getBytes());
        byte[] expected = encryptCipher.doFinal();

        assertArrayEquals("encrypted message", expected, result);
    }

    @Test
    public void testGetData() throws Exception {
        assumeCardPresent();

        OpenPGPCard pgpcard = OpenPGPCard.getCard();
        assertNotNull("card not found", pgpcard);

        byte[] result = pgpcard.getData(0x004F);
        assertNotNull("result", result);
        assertEquals("result length", 16, result.length);
    }

    @Test
    public void testGetAID() throws Exception {
        assumeCardPresent();

        OpenPGPCard pgpcard = OpenPGPCard.getCard();
        assertNotNull("card not found", pgpcard);

        byte[] result = pgpcard.getAID();
        assertNotNull("result", result);
        assertEquals("result length", 16, result.length);
        assertEquals("AID", "D27600012401", Hex.encodeHexString(result).substring(0, 12).toUpperCase());
    }

    @Test
    public void testGetVersion() throws Exception {
        assumeCardPresent();

        OpenPGPCard pgpcard = OpenPGPCard.getCard();
        assertNotNull("card not found", pgpcard);

        float version = pgpcard.getVersion();
        assertTrue("version < 2", version > 2);
    }

    @Test
    public void testGetAvailableKeys() throws Exception {
        assumeCardPresent();

        OpenPGPCard pgpcard = OpenPGPCard.getCard();
        assertNotNull("card not found", pgpcard);

        Set<OpenPGPCard.Key> keys = pgpcard.getAvailableKeys();
        assertNotNull("keys", keys);
        assertEquals("number of keys", pgpcard.supportsManageSecurityEnvironment() ? 3 : 2, keys.size());
    }

    @Test
    public void testGetKeyInfo() throws Exception {
        assumeCardPresent();

        OpenPGPCard pgpcard = OpenPGPCard.getCard();
        assertNotNull("card not found", pgpcard);

        OpenPGPCard.KeyInfo keyInfo = pgpcard.getKeyInfo(OpenPGPCard.Key.SIGNATURE);
        assertNotNull("key info", keyInfo);

        String fingerprint = Hex.encodeHexString(keyInfo.fingerprint).toUpperCase();
        assertEquals("Fingerprint", "97147A24770EFC11A41979BA5D37E9FA3D904376", fingerprint);
    }

    @Test
    public void testSelectData() throws Exception {
        assumeCardPresent();

        OpenPGPCard pgpcard = OpenPGPCard.getCard();
        assertNotNull("card not found", pgpcard);

        assumeTrue("OpenPGP card version 3+ required", pgpcard.getVersion() > 3);

        pgpcard.selectData(0x7F21, 0);
        byte[] result = pgpcard.getData(0x7F21);
        assertNotEquals("result is empty", 0, result.length);

        pgpcard.selectData(0x7F21, 1);
        result = pgpcard.getData(0x7F21);
        assertEquals("result is not empty", 0, result.length);

        pgpcard.selectData(0x7F21, 2);
        result= pgpcard.getData(0x7F21);
        assertEquals("result is not empty", 0, result.length);
    }

    @Test
    public void testGetAuthenticationCertificate() throws Exception {
        assumeCardPresent();

        OpenPGPCard pgpcard = OpenPGPCard.getCard();
        assertNotNull("card not found", pgpcard);

        byte[] result = pgpcard.getCertificate(OpenPGPCard.Key.AUTHENTICATION);
        assertNotNull("certificate", result);
    }

    @Test
    public void testPutData() throws Exception {
        assumeCardPresent();

        OpenPGPCard pgpcard = OpenPGPCard.getCard();
        assertNotNull("card not found", pgpcard);
        pgpcard.verify(0x00, 0x83, "12345678");

        byte[] backup = pgpcard.getData(0x7F21);
        byte[] data = new byte[backup.length];
        pgpcard.putData(0x7F21, data);

        assertArrayEquals("new data", data, pgpcard.getData(0x7F21));

        pgpcard.putData(0x7F21, backup);

        assertArrayEquals("backup data", backup, pgpcard.getData(0x7F21));
    }

    @Test
    public void testSupportsManageSecurityEnvironment() throws Exception {
        assumeCardPresent();

        OpenPGPCard pgpcard = OpenPGPCard.getCard();
        assertNotNull("card not found", pgpcard);

        assertTrue("MSE is not supported", pgpcard.supportsManageSecurityEnvironment());
    }
}
