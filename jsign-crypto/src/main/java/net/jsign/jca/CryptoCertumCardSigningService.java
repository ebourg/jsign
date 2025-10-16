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

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyStoreException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import javax.smartcardio.CardException;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;

import net.jsign.DigestAlgorithm;

/**
 * Signing service using a Certum smart card (cryptoCertum 3.6 with the Common Profile).
 *
 * @since 7.4
 */
public class CryptoCertumCardSigningService implements SigningService {

    private final CryptoCertumCard card;

    public CryptoCertumCardSigningService(String pin) throws CardException {
        CryptoCertumCard card = CryptoCertumCard.getCard();
        if (card == null) {
            throw new CardException("CryptoCertum card not found");
        }

        this.card = card;
        this.card.verify(pin);
    }

    @Override
    public String getName() {
        return "CryptoCertum";
    }

    @Override
    public List<String> aliases() throws KeyStoreException {
        try {
            return card.aliases();
        } catch (CardException e) {
            throw new KeyStoreException(e);
        }
    }

    @Override
    public Certificate[] getCertificateChain(String alias) throws KeyStoreException {
        LinkedHashMap<String, Certificate> certificates = new LinkedHashMap<>();

        try {
            CryptoCertumCard.Certificate certificate = card.getCertificate(alias);
            if (certificate != null) {
                certificates.put(alias, certificate.getCertificate());
            }
        } catch (CardException e) {
            throw new KeyStoreException(e);
        }

        return certificates.values().toArray(new Certificate[0]);
    }

    @Override
    public SigningServicePrivateKey getPrivateKey(String alias, char[] password) throws UnrecoverableKeyException {
        try {
            CryptoCertumCard.Key key = card.getKey(alias);
            if (key != null) {
                SigningServicePrivateKey privateKey = new SigningServicePrivateKey(alias, key.type == 0 ? "RSA" : "ECDSA", this);
                privateKey.getProperties().put("key", key);
                return privateKey;
            }
        } catch (CardException e) {
            throw (UnrecoverableKeyException) new UnrecoverableKeyException().initCause(e);
        }

        throw new UnrecoverableKeyException("Key '" + alias + "' not found on the card");
    }

    @Override
    public byte[] sign(SigningServicePrivateKey privateKey, String algorithm, byte[] data) throws GeneralSecurityException {
        DigestAlgorithm digestAlgorithm = DigestAlgorithm.of(algorithm.substring(0, algorithm.toLowerCase().indexOf("with")));
        byte[] digest = digestAlgorithm.getMessageDigest().digest(data);

        CryptoCertumCard.Key key = (CryptoCertumCard.Key) privateKey.getProperties().get("key");

        try {
            if ("RSA".equals(privateKey.getAlgorithm())) {
                // RSA
                return card.sign(key, digest);
            } else {
                // ECDSA
                byte[] content;
                if (digest.length > key.size / 8) {
                    content = Arrays.copyOf(digest, key.size / 8);
                } else {
                    content = digest;
                }

                return toEcdsaSigValue(card.sign(key, content));
            }
        } catch (CardException | IOException e) {
            throw new GeneralSecurityException(e);
        }
    }

    /**
     * ECDSA signatures are returned as two integers, r and s, concatenated together (IEEE P1363 format).
     * This method wraps the two integers into an Ecdsa-Sig-Value ASN.1 structure (RFC 3279, sec 2.2.3).
     */
    private byte[] toEcdsaSigValue(byte[] p1363signature) throws IOException {
        DERSequence ecdsaSigValue = new DERSequence(new ASN1Encodable[]{
                new ASN1Integer(new BigInteger(1, Arrays.copyOfRange(p1363signature, 0, p1363signature.length / 2))), // r
                new ASN1Integer(new BigInteger(1, Arrays.copyOfRange(p1363signature, p1363signature.length / 2, p1363signature.length))) // s
        });

        return ecdsaSigValue.getEncoded("DER");
    }
}
