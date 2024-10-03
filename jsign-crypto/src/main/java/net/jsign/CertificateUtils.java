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

package net.jsign;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;

/**
 * @since 5.0
 */
class CertificateUtils {

    private CertificateUtils() {
    }

    /**
     * Load the certificate chain from the specified PKCS#7 files.
     */
    public static Certificate[] loadCertificateChain(File file) throws IOException, CertificateException {
        try (FileInputStream in = new FileInputStream(file)) {
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            Collection<? extends Certificate> certificates = certificateFactory.generateCertificates(in);
            List<X509Certificate> list = (List) new ArrayList<>(certificates);
            list.sort(getChainComparator());
            return list.toArray(new Certificate[0]);
        }
    }

    /**
     * Returns a comparator that sorts the certificates in the chain in the order of the certification path,
     * from the end-entity certificate to the root CA.
     */
    public static Comparator<X509Certificate> getChainComparator() {
        return Comparator.comparing(X509Certificate::getBasicConstraints)
                .thenComparing(X509Certificate::getNotBefore, Comparator.reverseOrder())
                .thenComparing(X509Certificate::getSubjectX500Principal, Comparator.comparing(X500Principal::getName));
    }

    /**
     * Returns the authority information access extension of the specified certificate.
     *
     * @since 7.0
     */
    public static AuthorityInformationAccess getAuthorityInformationAccess(X509Certificate certificate) {
        byte[] aia = certificate.getExtensionValue(Extension.authorityInfoAccess.getId());
        return aia != null ? AuthorityInformationAccess.getInstance(ASN1OctetString.getInstance(aia).getOctets()) : null;
    }

    /**
     * Returns the issuer certificate URL of the specified certificate.
     *
     * @since 7.0
     */
    public static String getIssuerCertificateURL(X509Certificate certificate) {
        AuthorityInformationAccess aia = getAuthorityInformationAccess(certificate);
        if (aia != null) {
            for (AccessDescription access : aia.getAccessDescriptions()) {
                if (X509ObjectIdentifiers.id_ad_caIssuers.equals(access.getAccessMethod())) {
                    return access.getAccessLocation().getName().toString();
                }
            }
        }

        return null;
    }

    /**
     * Returns the issuer certificates of the specified certificate. Multiple issuer certificates may be returned
     * if the certificate is cross-signed.
     *
     * @since 7.0
     */
    public static Collection<X509Certificate> getIssuerCertificates(X509Certificate certificate) throws IOException, CertificateException {
        String certificateURL = getIssuerCertificateURL(certificate);
        if (certificateURL != null) {
            File cacheDirectory = new File(OSUtils.getCacheDirectory("jsign"), "certificates");
            HttpClient cache = new HttpClient(cacheDirectory, 90 * 24 * 3600 * 1000L);
            try (InputStream in = cache.getInputStream(new URL(certificateURL))) {
                CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
                return (Collection) certificateFactory.generateCertificates(in);
            }
        }

        return Collections.emptyList();
    }

    /**
     * Returns the certificate chain of the specified certificate up to the specified depth.
     *
     * @since 7.0
     */
    public static Collection<X509Certificate> getCertificateChain(X509Certificate certificate, int maxDepth) {
        List<X509Certificate> chain = new ArrayList<>();
        chain.add(certificate);

        if (maxDepth > 0 && !isSelfSigned(certificate)) {
            try {
                Collection<X509Certificate> issuers = getIssuerCertificates(certificate);
                for (X509Certificate issuer : issuers) {
                    chain.addAll(getCertificateChain(issuer, maxDepth - 1));
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        return chain;
    }

    /**
     * Tells if the specified certificate is self-signed.
     *
     * @since 7.0
     */
    public static boolean isSelfSigned(X509Certificate certificate) {
        return certificate.getSubjectDN().equals(certificate.getIssuerDN());
    }

    /**
     * Completes the specified chain with the missing issuer certificates.
     *
     * @since 7.0
     */
    public static List<X509Certificate> getFullCertificateChain(Collection<X509Certificate> chain) {
        Set<String> issuerNames = chain.stream().map(c -> c.getIssuerX500Principal().getName()).collect(Collectors.toSet());

        Set<String> missingIssuerNames = new LinkedHashSet<>(issuerNames);
        for (X509Certificate certificate : chain) {
            missingIssuerNames.remove(certificate.getSubjectX500Principal().getName());
        }
        Set<X509Certificate> orphanCertificates = new HashSet<>();
        for (X509Certificate certificate : chain) {
            if (missingIssuerNames.contains(certificate.getIssuerX500Principal().getName())) {
                orphanCertificates.add(certificate);
            }
        }

        List<X509Certificate> fullChain = new ArrayList<>(chain);
        for (X509Certificate orphanCertificate : orphanCertificates) {
            fullChain.remove(orphanCertificate);
            fullChain.addAll(getCertificateChain(orphanCertificate, 10));
        }

        return fullChain;
    }
}
