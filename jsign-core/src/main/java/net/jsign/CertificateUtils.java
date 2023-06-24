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
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.List;
import javax.security.auth.x500.X500Principal;

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
}
