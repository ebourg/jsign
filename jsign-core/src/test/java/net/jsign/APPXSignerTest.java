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
import java.security.KeyStore;

import org.apache.commons.compress.utils.SeekableInMemoryByteChannel;
import org.apache.commons.io.FileUtils;
import org.hamcrest.MatcherAssert;
import org.junit.Test;

import net.jsign.appx.APPXFile;

import static net.jsign.DigestAlgorithm.*;
import static org.hamcrest.Matchers.*;
import static org.junit.Assert.*;

public class APPXSignerTest {

    private static final String PRIVATE_KEY_PASSWORD = "password";
    private static final String ALIAS = "test";

    private KeyStore getKeyStore() throws Exception {
        return new KeyStoreBuilder().keystore("target/test-classes/keystores/keystore.jks").storepass("password").build();
    }

    @Test
    public void testSignPackage() throws Exception {
        File sourceFile = new File("target/test-classes/minimal.msix");
        File targetFile = new File("target/test-classes/minimal-signed.msix");

        FileUtils.copyFile(sourceFile, targetFile);

        AuthenticodeSigner signer = new AuthenticodeSigner(getKeyStore(), ALIAS, PRIVATE_KEY_PASSWORD).withTimestamping(false);

        try (Signable file = Signable.of(targetFile)) {
            signer.sign(file);

            SignatureAssert.assertSigned(file, SHA256);
            SignatureAssert.assertUuidEquals(file, "4BDFC50A-07CE-E24D-B76E-23C839A09FD1");
        }
    }

    @Test
    public void testSignBundle() throws Exception {
        File sourceFile = new File("target/test-classes/minimal.appxbundle");
        File targetFile = new File("target/test-classes/minimal-signed.appxbundle");

        FileUtils.copyFile(sourceFile, targetFile);

        AuthenticodeSigner signer = new AuthenticodeSigner(getKeyStore(), ALIAS, PRIVATE_KEY_PASSWORD).withTimestamping(false);

        try (Signable file = Signable.of(targetFile)) {
            signer.sign(file);

            SignatureAssert.assertSigned(file, SHA256);
            SignatureAssert.assertUuidEquals(file, "B3585F0F-DEAA-9A4B-A434-95742D92ECEB");
        }
    }

    @Test
    public void testSignTwice() throws Exception {
        File sourceFile = new File("target/test-classes/minimal.msix");
        File targetFile = new File("target/test-classes/minimal-signed-twice.msix");

        FileUtils.copyFile(sourceFile, targetFile);

        try (Signable file = Signable.of(targetFile)) {
            AuthenticodeSigner signer = new AuthenticodeSigner(getKeyStore(), ALIAS, PRIVATE_KEY_PASSWORD).withTimestamping(false);

            signer.sign(file);

            SignatureAssert.assertSigned(file, SHA256);

            // second signature
            signer.withDigestAlgorithm(SHA512);
            signer.sign(file);

            SignatureAssert.assertSigned(file, SHA256, SHA512);
        }
    }

    @Test
    public void testSignThreeTimes() throws Exception {
        File sourceFile = new File("target/test-classes/minimal.msix");
        File targetFile = new File("target/test-classes/minimal-signed-three-times.msix");

        FileUtils.copyFile(sourceFile, targetFile);

        try (Signable file = Signable.of(targetFile)) {
            AuthenticodeSigner signer = new AuthenticodeSigner(getKeyStore(), ALIAS, PRIVATE_KEY_PASSWORD)
                    .withDigestAlgorithm(SHA256)
                    .withTimestamping(true);

            signer.sign(file);

            SignatureAssert.assertSigned(file, SHA256);
            SignatureAssert.assertTimestamped("Invalid timestamp", file.getSignatures().get(0));

            // second signature
            signer.withDigestAlgorithm(SHA384);
            signer.withTimestamping(false);
            signer.sign(file);

            SignatureAssert.assertSigned(file, SHA256, SHA384);
            SignatureAssert.assertTimestamped("Timestamp corrupted after adding the second signature", file.getSignatures().get(0));

            // third signature
            signer.withDigestAlgorithm(SHA512);
            signer.withTimestamping(false);
            signer.sign(file);

            SignatureAssert.assertSigned(file, SHA256, SHA384, SHA512);
            SignatureAssert.assertTimestamped("Timestamp corrupted after adding the third signature", file.getSignatures().get(0));
        }
    }

    @Test
    public void testReplaceSignature() throws Exception {
        File sourceFile = new File("target/test-classes/minimal.msix");
        File targetFile = new File("target/test-classes/minimal-re-signed.msix");

        FileUtils.copyFile(sourceFile, targetFile);

        try (Signable file = Signable.of(targetFile)) {
            AuthenticodeSigner signer = new AuthenticodeSigner(getKeyStore(), ALIAS, PRIVATE_KEY_PASSWORD)
                    .withTimestamping(true);

            signer.sign(file);

            SignatureAssert.assertSigned(file, SHA256);
            SignatureAssert.assertTimestamped("Invalid timestamp", file.getSignatures().get(0));

            // second signature
            signer.withTimestamping(false);
            signer.withSignaturesReplaced(true);
            signer.sign(file);

            SignatureAssert.assertSigned(file, SHA256);
            SignatureAssert.assertNotTimestamped("Invalid timestamp", file.getSignatures().get(0));
        }
    }

    @Test
    public void testSignInMemory() throws Exception {
        File sourceFile = new File("target/test-classes/minimal.msix");

        byte[] data = FileUtils.readFileToByteArray(sourceFile);

        SeekableInMemoryByteChannel channel = new SeekableInMemoryByteChannel(data);

        AuthenticodeSigner signer = new AuthenticodeSigner(getKeyStore(), ALIAS, PRIVATE_KEY_PASSWORD).withTimestamping(false);

        try (Signable file = new APPXFile(channel)) {
            signer.sign(file);
            data = channel.array();
        }

        try (Signable file = new APPXFile(new SeekableInMemoryByteChannel(data))) {
            SignatureAssert.assertSigned(file, SHA256);
        }
    }

    @Test
    public void testSignWithMismatchedCertificate() throws Exception {
        File sourceFile = new File("target/test-classes/minimal.msix");
        File targetFile = new File("target/test-classes/minimal-signed-with-mismatched-certificate.msix");

        FileUtils.copyFile(sourceFile, targetFile);

        KeyStore keystore = new KeyStoreBuilder().storetype("NONE")
                .keyfile("target/test-classes/keystores/privatekey.pkcs8.pem")
                .certfile("target/test-classes/keystores/jsign-test-certificate-partial-chain.pem")
                .build();
        AuthenticodeSigner signer = new AuthenticodeSigner(keystore, "jsign", "").withTimestamping(false);

        try (Signable file = Signable.of(targetFile)) {
            Exception e = assertThrows(Exception.class, () -> signer.sign(file));
            MatcherAssert.assertThat(e.getMessage(), matchesPattern("The app manifest publisher name (.*) must match the subject name of the signing certificate (.*)"));
        }
    }
}
