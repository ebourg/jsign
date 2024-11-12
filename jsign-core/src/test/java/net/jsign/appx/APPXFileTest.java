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

package net.jsign.appx;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import javax.security.auth.x500.X500Principal;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.junit.Test;

import net.jsign.AuthenticodeSigner;
import net.jsign.KeyStoreBuilder;

import static java.nio.charset.StandardCharsets.*;
import static net.jsign.DigestAlgorithm.*;
import static net.jsign.SignatureAssert.*;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class APPXFileTest {

    @Test
    public void testGetSignaturesFromUnsignedPackage() throws Exception {
        try (APPXFile file = new APPXFile(new File("target/test-classes/minimal.msix"))) {
            assertTrue("signature found", file.getSignatures().isEmpty());
        }
    }

    @Test
    public void testGetSignaturesFromSignedPackage() throws Exception {
        try (APPXFile file = new APPXFile(new File("target/test-classes/minimal-signed-by-signtool.msix"))) {
            assertFalse("signature not found", file.getSignatures().isEmpty());
        }
    }

    @Test
    public void testAddContentType() throws Exception {
        File unsignedFile = new File("target/test-classes/minimal.msix");
        File modified = new File("target/test-classes/minimal-with-content-types-modified.msix");

        FileUtils.copyFile(unsignedFile, modified);

        // modify the content types
        try (APPXFile msix = new APPXFile(modified)) {
            msix.addContentType("/foo.txt", "text/foo");
            msix.addContentType("/foo.txt", "text/foo");
        }

        try (APPXFile msix = new APPXFile(modified)) {
            String contentTypes = new String(IOUtils.toByteArray(msix.getInputStream("[Content_Types].xml")), UTF_8);
            assertTrue("missing content type", contentTypes.contains("<Override PartName=\"/foo.txt\" ContentType=\"text/foo\"/>"));
            assertEquals("number of content types added", 1, StringUtils.countMatches(contentTypes, "text/foo"));
        }
    }

    @Test
    public void testRemoveSignature() throws Exception {
        File sourceFile = new File("target/test-classes/minimal.msix");
        File targetFile = new File("target/test-classes/minimal-unsigned.msix");

        FileUtils.copyFile(sourceFile, targetFile);

        KeyStore keystore = new KeyStoreBuilder().keystore("target/test-classes/keystores/keystore.jks").storepass("password").build();
        AuthenticodeSigner signer = new AuthenticodeSigner(keystore, "test", "password").withTimestamping(false);

        try (APPXFile file = new APPXFile(targetFile)) {
            file.setSignature(null);
            signer.sign(file);
            assertSigned(file, SHA256);
            file.setSignature(null);
            assertNotSigned(file);
        }
    }

    @Test
    public void testIsBundle() throws Exception {
        try (APPXFile file = new APPXFile(new File("target/test-classes/minimal.msix"))) {
            assertFalse("minimal.msix is a bundle", file.isBundle());
        }
        try (APPXFile file = new APPXFile(new File("target/test-classes/minimal.appxbundle"))) {
            assertTrue("minimal.appxbundle is not a bundle", file.isBundle());
        }
    }

    @Test
    public void testGetPackagePublisher() throws Exception {
        try (APPXFile file = new APPXFile(new File("target/test-classes/minimal.msix"))) {
            assertEquals("Publisher", "CN=Jsign Code Signing Test Certificate 2024 (RSA)", file.getPublisher());
        }
    }

    @Test
    public void testGetBundlePublisher() throws Exception {
        try (APPXFile file = new APPXFile(new File("target/test-classes/minimal.appxbundle"))) {
            assertEquals("Publisher", "CN=Jsign Code Signing Test Certificate 2024 (RSA)", file.getPublisher());
        }
    }

    public static Certificate getCertificate() throws IOException, CertificateException {
        try (FileInputStream in = new FileInputStream("target/test-classes/keystores/jsign-test-certificate.pem")) {
            return CertificateFactory.getInstance("X.509").generateCertificates(in).iterator().next();
        }
    }

    @Test
    public void testValidateWithMatchingPublisher() throws Exception {
        try (APPXFile file = new APPXFile(new File("target/test-classes/minimal.msix"))) {
            file.validate(getCertificate());
        }
    }

    @Test
    public void testValidateWithMismatchingPublisher() throws Exception {
        try (APPXFile file = spy(new APPXFile(new File("target/test-classes/minimal.msix")))) {
            when(file.getPublisher()).thenReturn("CN=Jsign Code Signing Test Certificate 1977 (RSA)");
            Exception e = assertThrows(IllegalArgumentException.class, () -> file.validate(getCertificate()));
            assertEquals("message", "The app manifest publisher name (CN=Jsign Code Signing Test Certificate 1977 (RSA)) must match the subject name of the signing certificate (CN=Jsign Code Signing Test Certificate 2024 (RSA))", e.getMessage());
        }
    }

    @Test
    public void testValidateWithReorderedPublisher() throws Exception {
        try (APPXFile file = spy(new APPXFile(new File("target/test-classes/minimal.msix")))) {
            when(file.getPublisher()).thenReturn("C=US, S=New York,  L=New York, O=\"COMPANY, INC.\",CN=\"COMPANY, INC.\"");

            X509Certificate certificate = spy((X509Certificate) getCertificate());
            when(certificate.getSubjectX500Principal()).thenReturn(new X500Principal("CN=\"COMPANY, INC.\",O=\"COMPANY, INC.\",L=New York,ST=New York,C=US"));
            file.validate(certificate);
        }
    }

    @Test
    public void testValidateWithMissingPublisher() throws Exception {
        try (APPXFile file = spy(new APPXFile(new File("target/test-classes/minimal.msix")))) {
            when(file.getPublisher()).thenReturn(null);
            Exception e = assertThrows(IllegalArgumentException.class, () -> file.validate(getCertificate()));
            assertEquals("message", "The app manifest publisher name (null) must match the subject name of the signing certificate (CN=Jsign Code Signing Test Certificate 2024 (RSA))", e.getMessage());
        }
    }
}
