/*
 * Copyright 2026 Emmanuel Bourg
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
import java.security.KeyStore;
import java.util.Date;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.junit.Test;

import net.jsign.timestamp.TimestampingMode;

import static net.jsign.DigestAlgorithm.*;
import static org.junit.Assert.*;

public class SignatureUtilsTest {

    private static final String PRIVATE_KEY_PASSWORD = "password";
    private static final String ALIAS = "test";

    private KeyStore getKeyStore() throws Exception {
        return new KeyStoreBuilder().keystore("target/test-classes/keystores/keystore.jks").storepass("password").build();
    }

    @Test
    public void testGetTimestampDateAndCertificateAuthenticode() throws Exception {
        testGetTimestampDateAndCertificate(TimestampingMode.AUTHENTICODE);
    }

    @Test
    public void testGetTimestampDateAndCertificateRFC3161() throws Exception {
        testGetTimestampDateAndCertificate(TimestampingMode.RFC3161);
    }

    public void testGetTimestampDateAndCertificate(TimestampingMode mode) throws Exception {
        File sourceFile = new File("target/test-classes/wineyes.exe");
        File targetFile = new File("target/test-classes/wineyes-timestamped-" + mode.name().toLowerCase() + ".exe");

        FileUtils.copyFile(sourceFile, targetFile);

        AuthenticodeSigner signer = new AuthenticodeSigner(getKeyStore(), ALIAS, PRIVATE_KEY_PASSWORD);
        signer.withDigestAlgorithm(SHA256);
        signer.withTimestamping(true);
        signer.withTimestampingMode(mode);

        try (Signable signable = Signable.of(targetFile)) {
            signer.sign(signable);

            SignatureAssert.assertTimestamped("Invalid timestamp", signable.getSignatures().get(0));

            Date date = SignatureUtils.getTimestampDate(signable.getSignatures().get(0));
            assertNotNull("null timestamp date", date);

            X509CertificateHolder certificate = SignatureUtils.getTimestampCertificate(signable.getSignatures().get(0));
            assertNotNull("null timestamp certificate", certificate);
        }
    }

    @Test
    public void testGetDigestInfo() throws Exception {
        File sourceFile = new File("target/test-classes/wineyes.exe");
        File targetFile = new File("target/test-classes/wineyes-signed.exe");

        FileUtils.copyFile(sourceFile, targetFile);

        AuthenticodeSigner signer = new AuthenticodeSigner(getKeyStore(), ALIAS, PRIVATE_KEY_PASSWORD);

        try (Signable signable = Signable.of(targetFile)) {
            signer.sign(signable);

            DigestInfo digestInfo = SignatureUtils.getDigestInfo(signable.getSignatures().get(0));
            assertNotNull("null digest info", digestInfo);
        }
    }

    @Test
    public void testGetDigestInfoNuGet() throws Exception {
        File sourceFile = new File("target/test-classes/nuget/minimal.1.0.0.nupkg");
        File targetFile = new File("target/test-classes/nuget/minimal.1.0.0-signed.nupkg");

        FileUtils.copyFile(sourceFile, targetFile);

        AuthenticodeSigner signer = new AuthenticodeSigner(getKeyStore(), ALIAS, PRIVATE_KEY_PASSWORD);

        try (Signable signable = Signable.of(targetFile)) {
            signer.sign(signable);

            DigestInfo digestInfo = SignatureUtils.getDigestInfo(signable.getSignatures().get(0));
            assertNotNull("null digest info", digestInfo);
        }
    }
}
