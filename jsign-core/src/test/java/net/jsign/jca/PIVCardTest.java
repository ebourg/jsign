/**
 * Copyright 2024 Emmanuel Bourg
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

import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Set;
import javax.crypto.Cipher;

import org.junit.Test;

import net.jsign.DigestAlgorithm;

import static net.jsign.jca.PIVCard.Key.*;
import static org.junit.Assert.*;
import static org.junit.Assume.*;

public class PIVCardTest {

    public static void assumeCardPresent() throws Exception {
        assumeTrue("PIV card not found", SmartCard.getTerminal("Yubikey") != null);
    }

    @Test
    public void testGetCard() throws Exception {
        assumeCardPresent();

        assertNotNull("card not found", PIVCard.getCard());
    }

    @Test
    public void testSignRSA() throws Exception {
        assumeCardPresent();

        PIVCard card = PIVCard.getCard();
        assertNotNull("card not found", card);
        card.verify("123456");

        PIVCard.Key key = SIGNATURE;
        int keyLength = card.getKeyInfo(key).size;

        byte[] message = "Hello PIV card".getBytes();
        byte[] result = card.sign(key, message);

        assertNotNull(result);

        assertEquals("result length (bits)", keyLength, result.length * 8);

        // decrypt the message with the public key
        PublicKey publicKey = card.getCertificate(key).getPublicKey();
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        cipher.update(result);
        byte[] decrypted = cipher.doFinal();

        assertArrayEquals("encrypted message", message, decrypted);
    }

    @Test
    public void testSignSHA1withECDSA() throws Exception {
        testSignECDSA(DigestAlgorithm.SHA1);
    }

    @Test
    public void testSignSHA256withECDSA() throws Exception {
        testSignECDSA(DigestAlgorithm.SHA256);
    }

    @Test
    public void testSignSHA384withECDSA() throws Exception {
        testSignECDSA(DigestAlgorithm.SHA384);
    }

    @Test
    public void testSignSHA512withECDSA() throws Exception {
        testSignECDSA(DigestAlgorithm.SHA512);
    }

    public void testSignECDSA(DigestAlgorithm digestAlgorithm) throws Exception {
        assumeCardPresent();

        PIVCard card = PIVCard.getCard();
        assertNotNull("card not found", card);
        card.verify("123456");

        PIVCard.Key key = CARD_AUTHENTICATION;
        int keyLength = card.getKeyInfo(key).size;

        byte[] message = "Hello PIV card".getBytes();

        byte[] digest = digestAlgorithm.getMessageDigest().digest(message);
        if (digest.length > keyLength / 8) {
            digest = Arrays.copyOf(digest, keyLength / 8);
        }

        byte[] result = card.sign(key, digest);

        assertNotNull(result);

        // verify the signature
        Signature signature = Signature.getInstance(digestAlgorithm.name() + "withECDSA");
        signature.initVerify(card.getCertificate(key));
        signature.update(message);
        assertTrue(signature.getAlgorithm() + " signature verification failed", signature.verify(result));
    }

    @Test
    public void testGetData() throws Exception {
        assumeCardPresent();

        PIVCard card = PIVCard.getCard();
        assertNotNull("card not found", card);

        byte[] result = card.getData(0x005FC102); // Cardholder UUID
        assertNotNull(result);
        assertTrue("result length", result.length >= 61);
    }

    @Test
    public void testGetVersion() throws Exception {
        assumeCardPresent();

        PIVCard pivcard = PIVCard.getCard();
        assertNotNull("card not found", pivcard);

        String version = pivcard.getVersion();
        assertNotNull(version);
    }

    @Test
    public void testGetAvailableKeys() throws Exception {
        assumeCardPresent();

        PIVCard card = PIVCard.getCard();
        assertNotNull("card not found", card);

        Set<PIVCard.Key> keys = card.getAvailableKeys();

        assertNotNull(keys);
        assertEquals("number of keys", 2, keys.size());
    }

    @Test
    public void testGetKeyInfo() throws Exception {
        assumeCardPresent();

        PIVCard card = PIVCard.getCard();
        assertNotNull("card not found", card);

        PIVCard.KeyInfo info = card.getKeyInfo(SIGNATURE);
        assertNotNull("key info not found", info);
        assertEquals("Algorithm", "RSA", info.algorithm);
        assertEquals("Size", 2048, info.size);
        assertEquals("RSA-2048 identifier", 7, info.algorithmId);
    }

    @Test
    public void testGetCertificate() throws Exception {
        assumeCardPresent();

        PIVCard card = PIVCard.getCard();
        assertNotNull("card not found", card);

        X509Certificate certificate = (X509Certificate) card.getCertificate(SIGNATURE);
        assertNotNull("certificate not found", certificate);
        assertEquals("subject", "CN=Jsign Code Signing Test Certificate 2022 (RSA)", certificate.getSubjectDN().getName());
    }

    @Test
    public void testGetKey() {
        assertNull(PIVCard.Key.of(null));
        assertNull(PIVCard.Key.of("JSIGN"));

        for (PIVCard.Key key : PIVCard.Key.values()) {
            assertEquals(key.name() + " key with uppercase name", key, PIVCard.Key.of(key.name()));
            assertEquals(key.name() + " key with lowercase name", key, PIVCard.Key.of(key.name().toLowerCase()));
            assertEquals(key.name() + " key with alias", key, PIVCard.Key.of(key.alias));

            String slot = Integer.toHexString(key.slot);
            assertEquals(key.name() + " key with slot " + slot, key, PIVCard.Key.of(slot));
        }
    }
}
