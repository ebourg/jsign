/*
 * Copyright 2025 Emmanuel Bourg
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
import java.security.cert.X509Certificate;
import java.util.List;
import javax.crypto.Cipher;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.junit.Before;
import org.junit.Test;

import net.jsign.DigestAlgorithm;

import static org.junit.Assert.*;
import static org.junit.Assume.*;

public class CryptoCertumCardTest {

    public static void assumeCardPresent() {
        try {
            CardChannel channel = SmartCard.openChannel(CryptoCertumCard.ESIGN_COMMON_PROFILE_AID);
            assumeTrue("CryptoCertum card not found", channel != null);
            channel.getCard().disconnect(false);
        } catch (CardException e) {
            assumeNoException("CryptoCertum card not found", e);
        }
    }

    @Before
    public void setUp() throws Exception {
        assumeCardPresent();
    }

    @Test
    public void testGetCard() throws Exception {
        assertNotNull("card not found", CryptoCertumCard.getCard());
    }

    @Test
    public void testGetChallenge() throws Exception {
        CryptoCertumCard card = CryptoCertumCard.getCard();
        assertNotNull("card not found", card);

        byte[] challenge = card.getChallenge(8);
        assertNotNull(challenge);
    }

    @Test
    public void testGetEntries() throws Exception {
        CryptoCertumCard card = CryptoCertumCard.getCard();
        assertNotNull("card not found", card);

        List<CryptoCertumCard.Entry> entries = card.getEntries();
        assertNotNull(entries);
        assertFalse(entries.isEmpty());
    }

    @Test
    public void testGetName() throws Exception {
        CryptoCertumCard card = CryptoCertumCard.getCard();
        assertNotNull("card not found", card);

        List<CryptoCertumCard.Entry> entries = card.getEntries();
        for (CryptoCertumCard.Entry entry : entries) {
            assertNotNull("name is null for entry " + entry.fid(), entry.name());
        }
    }

    @Test
    public void testGetCertificate() throws Exception {
        CryptoCertumCard card = CryptoCertumCard.getCard();
        assertNotNull("card not found", card);

        List<CryptoCertumCard.Entry> entries = card.getEntries();
        for (CryptoCertumCard.Entry entry : entries) {
            if (entry instanceof CryptoCertumCard.Certificate) {
                X509Certificate certificate = ((CryptoCertumCard.Certificate) entry).getCertificate();
                assertNotNull("certificate is null for entry " + entry.fid(), certificate);
            }
        }
    }

    @Test
    public void testGetKeyData() throws Exception {
        CryptoCertumCard card = CryptoCertumCard.getCard();
        assertNotNull("card not found", card);

        card.verify("123456");

        byte[] data = card.getKeyData(0x22);
        assertNotNull("key data", data);
    }

    @Test
    public void testSign() throws Exception {
        CryptoCertumCard card = CryptoCertumCard.getCard();
        assertNotNull("card not found", card);

        card.verify("123456");

        CryptoCertumCard.Key key = (CryptoCertumCard.Key) card.getEntries().stream()
                .filter(entry -> entry instanceof CryptoCertumCard.Key).findFirst().orElse(null);
        assertNotNull("no key found on the card", key);

        byte[] hash = DigestAlgorithm.SHA256.getMessageDigest().digest("Hello CryptoCertum card".getBytes());
        byte[] result = card.sign(key, hash);

        assertNotNull("result", result);
        assertEquals("result length (bits)", key.size, result.length * 8);


        // decrypt the message with the public key
        CryptoCertumCard.Certificate certificate = card.getCertificate(key.name());
        assertNotNull("no certificate found on the card", certificate);

        PublicKey publicKey = certificate.getCertificate().getPublicKey();
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        cipher.update(result);
        byte[] decrypted = cipher.doFinal();

        DigestInfo digestInfo = new DigestInfo(new AlgorithmIdentifier(DigestAlgorithm.SHA256.oid, DERNull.INSTANCE), hash);
        byte[] digest = digestInfo.getEncoded(ASN1Encoding.DER);

        assertArrayEquals("encrypted message", digest, decrypted);
    }
}
