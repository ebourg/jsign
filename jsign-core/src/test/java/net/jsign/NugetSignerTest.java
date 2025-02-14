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

package net.jsign;

import java.io.File;
import java.security.KeyStore;

import org.apache.commons.compress.utils.SeekableInMemoryByteChannel;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.junit.Test;

import net.jsign.nuget.NugetFile;
import net.jsign.timestamp.TimestampingMode;

import static net.jsign.DigestAlgorithm.*;
import static org.junit.Assert.*;

public class NugetSignerTest {

    private static final String PRIVATE_KEY_PASSWORD = "password";
    private static final String ALIAS = "test";

    private KeyStore getKeyStore() throws Exception {
        return new KeyStoreBuilder().keystore("target/test-classes/keystores/keystore.jks").storepass("password").build();
    }

    @Test
    public void testSign() throws Exception {
        File sourceFile = new File("target/test-classes/nuget/minimal.1.0.0.nupkg");
        File targetFile = new File("target/test-classes/nuget/minimal.1.0.0-signed.nupkg");

        FileUtils.copyFile(sourceFile, targetFile);

        AuthenticodeSigner signer = new AuthenticodeSigner(getKeyStore(), ALIAS, PRIVATE_KEY_PASSWORD).withTimestamping(false);

        try (Signable file = Signable.of(targetFile)) {
            signer.sign(file);

            SignatureAssert.assertSigned(file, SHA256);

            // verify the signed attributes
            SignatureAssert.assertSignedAttribute("commitment type indication", file, PKCSObjectIdentifiers.id_aa_ets_commitmentType);
            SignatureAssert.assertSignedAttribute("signing certificate v2", file, PKCSObjectIdentifiers.id_aa_signingCertificateV2);
            SignatureAssert.assertSignedAttribute("signing time", file, CMSAttributes.signingTime);
        }
    }

    @Test
    public void testSignTwice() throws Exception {
        File sourceFile = new File("target/test-classes/nuget/minimal.1.0.0.nupkg");
        File targetFile = new File("target/test-classes/nuget/minimal.1.0.0-signed-twice.nupkg");

        FileUtils.copyFile(sourceFile, targetFile);

        try (Signable file = Signable.of(targetFile)) {
            AuthenticodeSigner signer = new AuthenticodeSigner(getKeyStore(), ALIAS, PRIVATE_KEY_PASSWORD).withTimestamping(false);

            signer.sign(file);

            SignatureAssert.assertSigned(file, SHA256);

            // second signature
            signer.withDigestAlgorithm(SHA512);

            Exception e = assertThrows(SignerException.class, () -> signer.sign(file));
            assertTrue(e.getMessage().contains("The file is already signed"));

            SignatureAssert.assertSigned(file, SHA256);
        }
    }

    @Test
    public void testReplaceSignature() throws Exception {
        File sourceFile = new File("target/test-classes/nuget/minimal.1.0.0.nupkg");
        File targetFile = new File("target/test-classes/nuget/minimal.1.0.0-re-signed.nupkg");

        FileUtils.copyFile(sourceFile, targetFile);

        try (Signable file = Signable.of(targetFile)) {
            AuthenticodeSigner signer = new AuthenticodeSigner(getKeyStore(), ALIAS, PRIVATE_KEY_PASSWORD)
                    .withTimestamping(false);

            signer.sign(file);

            SignatureAssert.assertSigned(file, SHA256);

            // second signature
            signer.withDigestAlgorithm(SHA512);
            signer.withTimestamping(false);
            signer.withSignaturesReplaced(true);
            signer.sign(file);

            SignatureAssert.assertSigned(file, SHA512);
        }
    }

    @Test
    public void testTimestampAuthenticode() throws Exception {
        testTimestamp(TimestampingMode.AUTHENTICODE, SHA256);
    }

    @Test
    public void testTimestampRFC3161() throws Exception {
        testTimestamp(TimestampingMode.RFC3161, SHA384);
    }

    public void testTimestamp(TimestampingMode mode, DigestAlgorithm alg) throws Exception {
        File sourceFile = new File("target/test-classes/nuget/minimal.1.0.0.nupkg");
        File targetFile = new File("target/test-classes/nuget/minimal.1.0.0-timestamped-" + mode.name().toLowerCase() + ".nupkg");

        FileUtils.copyFile(sourceFile, targetFile);

        AuthenticodeSigner signer = new AuthenticodeSigner(getKeyStore(), ALIAS, PRIVATE_KEY_PASSWORD);
        signer.withDigestAlgorithm(alg);
        signer.withTimestamping(true);
        signer.withTimestampingMode(mode);

        try (Signable file = Signable.of(targetFile)) {
            signer.sign(file);

            SignatureAssert.assertSigned(file, alg);
            SignatureAssert.assertTimestamped("Invalid timestamp", file.getSignatures().get(0));
        }
    }

    @Test
    public void testSignInMemory() throws Exception {
        File sourceFile = new File("target/test-classes/nuget/minimal.1.0.0.nupkg");

        byte[] data = FileUtils.readFileToByteArray(sourceFile);

        SeekableInMemoryByteChannel channel = new SeekableInMemoryByteChannel(data);

        AuthenticodeSigner signer = new AuthenticodeSigner(getKeyStore(), ALIAS, PRIVATE_KEY_PASSWORD).withTimestamping(false);

        try (Signable file = new NugetFile(channel)) {
            signer.sign(file);
            data = channel.array();
        }

        try (Signable file = new NugetFile(new SeekableInMemoryByteChannel(data))) {
            SignatureAssert.assertSigned(file, SHA256);
        }
    }
}
