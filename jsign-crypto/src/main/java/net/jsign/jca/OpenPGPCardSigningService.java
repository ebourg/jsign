/*
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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStoreException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
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
 * Signing service using an OpenPGP smart card. OpenPGP cards contain up to 3 keys (for signing, authentication
 * and encryption), but all can be used for code signing. The card may contain an X.509 certificate for each key,
 * the intermediate certificates have to be provided externally.
 *
 * @since 5.0
 */
public class OpenPGPCardSigningService implements SigningService {

    private final OpenPGPCard pgpcard;

    /** Source for the certificates */
    private final Function<String, Certificate[]> certificateStore;

    public OpenPGPCardSigningService(String pin, Function<String, Certificate[]> certificateStore) throws CardException {
        this(null, pin, certificateStore);
    }

    public OpenPGPCardSigningService(String cardname, String pin, Function<String, Certificate[]> certificateStore) throws CardException {
        OpenPGPCard pgpcard = OpenPGPCard.getCard(cardname);
        if (pgpcard == null) {
            throw new CardException("OpenPGP card not found");
        }

        this.certificateStore = certificateStore;
        this.pgpcard = pgpcard;
        this.pgpcard.verify(pin);
    }

    @Override
    public String getName() {
        return "OPENPGP";
    }

    @Override
    public List<String> aliases() throws KeyStoreException {
        try {
            Set<OpenPGPCard.Key> keys = pgpcard.getAvailableKeys();
            return keys.stream().map(Enum::name).collect(Collectors.toList());
        } catch (CardException e) {
            throw new KeyStoreException(e);
        }
    }

    @Override
    public Certificate[] getCertificateChain(String alias) throws KeyStoreException {
        Map<String, Certificate> certificates = new LinkedHashMap<>();

        // add the certificate from the card
        try {
            OpenPGPCard.Key key = OpenPGPCard.Key.valueOf(alias);
            ByteArrayInputStream data = new ByteArrayInputStream(pgpcard.getCertificate(key));
            data.mark(0);

            if (data.available() > 0) {
                CertificateFactory factory = CertificateFactory.getInstance("X.509");
                try {
                    // The format of the certificate on the card is unspecified, let's be optimistic and assume
                    // it's a full chain in PKCS#7 format (unlikely considering the size constraints of the card
                    // but who knows, some day maybe)
                    Certificate[] chain = factory.generateCertPath(data).getCertificates().toArray(new Certificate[0]);
                    for (Certificate certificate : chain) {
                        String subject = ((X509Certificate) certificate).getSubjectX500Principal().getName();
                        certificates.put(subject, certificate);
                    }
                } catch (CertificateException e) {
                    data.reset();
                    Certificate certificate = factory.generateCertificate(data);
                    String subject = ((X509Certificate) certificate).getSubjectX500Principal().getName();
                    certificates.put(subject, certificate);
                }
            }
        } catch (CardException | CertificateException e) {
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
        OpenPGPCard.KeyInfo keyInfo;
        try {
            keyInfo = pgpcard.getKeyInfo(OpenPGPCard.Key.valueOf(alias));
        } catch (CardException e) {
            throw (UnrecoverableKeyException) new UnrecoverableKeyException("Unable to retrieve the info for key " + alias).initCause(e);
        }

        String algorithm;
        if (keyInfo.isRSA()) {
            algorithm = "RSA";
        } else if (keyInfo.isEC()) {
            algorithm = "ECDSA";
        } else {
            throw new UnrecoverableKeyException("Unsupported key algorithm " + keyInfo.algorithm + " for key " + alias);
        }

        return new SigningServicePrivateKey(alias, algorithm, this);
    }

    @Override
    public byte[] sign(SigningServicePrivateKey privateKey, String algorithm, byte[] data) throws GeneralSecurityException {
        DigestAlgorithm digestAlgorithm = DigestAlgorithm.of(algorithm.substring(0, algorithm.toLowerCase().indexOf("with")));
        byte[] digest = digestAlgorithm.getMessageDigest().digest(data);

        try {
            byte[] content;
            if ("RSA".equals(privateKey.getAlgorithm())) {
                // RSA
                DigestInfo digestInfo = new DigestInfo(new AlgorithmIdentifier(digestAlgorithm.oid, DERNull.INSTANCE), digest);
                content = digestInfo.getEncoded(ASN1Encoding.DER);
            } else {
                // ECDSA
                OpenPGPCard.KeyInfo keyInfo = pgpcard.getKeyInfo(OpenPGPCard.Key.valueOf(privateKey.getId()));
                if (digest.length > keyInfo.size / 8) {
                    content = Arrays.copyOf(digest, keyInfo.size / 8);
                } else {
                    content = digest;
                }
            }
            return  pgpcard.sign(OpenPGPCard.Key.valueOf(privateKey.getId()), content);
        } catch (CardException | IOException e) {
            throw new GeneralSecurityException(e);
        }
    }
}
