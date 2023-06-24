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
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import org.junit.Test;

import static org.junit.Assert.*;

public class CertificateUtilsTest {

    @Test
    public void testLoadCertificateChain() throws Exception {
        Certificate[] chain = CertificateUtils.loadCertificateChain(new File("src/test/resources/keystores/jsign-test-certificate-full-chain.pem"));
        X509Certificate certificate = (X509Certificate) chain[0];
        assertEquals("first certificate", "CN=Jsign Code Signing Test Certificate 2022 (RSA)", certificate.getSubjectX500Principal().getName());
    }

    @Test
    public void testLoadCertificateChainReversed() throws Exception {
        Certificate[] chain = CertificateUtils.loadCertificateChain(new File("src/test/resources/keystores/jsign-test-certificate-full-chain-reversed.pem"));
        X509Certificate certificate = (X509Certificate) chain[0];
        assertEquals("first certificate", "CN=Jsign Code Signing Test Certificate 2022 (RSA)", certificate.getSubjectX500Principal().getName());
    }
}
