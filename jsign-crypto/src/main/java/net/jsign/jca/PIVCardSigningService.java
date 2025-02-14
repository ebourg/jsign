/*
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

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStoreException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;
import javax.smartcardio.CardException;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;

import net.jsign.DigestAlgorithm;

/**
 * Signing service using an PIV smart card. PIV cards contain up to 24 keys usable to signing,
 * along with the X.509 certificates.
 *
 * @since 6.0
 */
public class PIVCardSigningService implements SigningService {

    private final PIVCard card;

    /** Source for the certificates */
    private final Function<String, Certificate[]> certificateStore;

    public PIVCardSigningService(String cardname, String pin, Function<String, Certificate[]> certificateStore) throws CardException {
        PIVCard card = PIVCard.getCard(cardname);
        if (card == null) {
            throw new CardException("PIV card not found");
        }

        this.certificateStore = certificateStore;
        this.card = card;
        this.card.verify(pin);
    }

    @Override
    public String getName() {
        return "PIV";
    }

    @Override
    public List<String> aliases() throws KeyStoreException {
        try {
            Set<PIVCard.Key> keys = card.getAvailableKeys();
            return keys.stream().map(Enum::name).collect(Collectors.toList());
        } catch (CardException e) {
            throw new KeyStoreException(e);
        }
    }

    @Override
    public Certificate[] getCertificateChain(String alias) throws KeyStoreException {
        Map<String, Certificate> certificates = new LinkedHashMap<>();

        PIVCard.Key key = PIVCard.Key.of(alias);
        if (key == null) {
            return null;
        }

        // add the certificate from the card
        try {
            Certificate certificate = card.getCertificate(key);
            if (certificate == null) {
                return null;
            }
            String subject = ((X509Certificate) certificate).getSubjectX500Principal().getName();
            certificates.put(subject, certificate);
        } catch (CardException e) {
            throw new KeyStoreException(e);
        }

        // add the certificates from the certificate store
        if (certificateStore != null) {
            for (Certificate certificate : certificateStore.apply(alias)) {
                String subject = ((X509Certificate) certificate).getSubjectX500Principal().getName();
                certificates.put(subject, certificate);
            }
        }

        return certificates.values().toArray(new Certificate[0]);
    }

    @Override
    public SigningServicePrivateKey getPrivateKey(String alias, char[] password) throws UnrecoverableKeyException {
        PIVCard.Key key = PIVCard.Key.of(alias);

        try {
            Certificate certificate = card.getCertificate(key);
            return new SigningServicePrivateKey(alias, certificate.getPublicKey().getAlgorithm(), this);
        } catch (CardException e) {
            throw (UnrecoverableKeyException) new UnrecoverableKeyException("Unable to retrieve the info for key " + alias).initCause(e);
        }
    }

    @Override
    public byte[] sign(SigningServicePrivateKey privateKey, String algorithm, byte[] data) throws GeneralSecurityException {
        DigestAlgorithm digestAlgorithm = DigestAlgorithm.of(algorithm.substring(0, algorithm.toLowerCase().indexOf("with")));
        byte[] digest = digestAlgorithm.getMessageDigest().digest(data);

        PIVCard.Key key = PIVCard.Key.of(privateKey.getId());

        try {
            PIVCard.KeyInfo keyInfo = card.getKeyInfo(key);

            byte[] content;
            if ("RSA".equals(privateKey.getAlgorithm())) {
                // RSA
                DigestInfo digestInfo = new DigestInfo(new AlgorithmIdentifier(digestAlgorithm.oid, DERNull.INSTANCE), digest);
                content = digestInfo.getEncoded(ASN1Encoding.DER);
            } else {
                // ECDSA
                if (digest.length > keyInfo.size / 8) {
                    content = Arrays.copyOf(digest, keyInfo.size / 8);
                } else {
                    content = digest;
                }
            }
            return  card.sign(key, content);
        } catch (CardException | IOException e) {
            throw new GeneralSecurityException(e);
        }
    }
}
