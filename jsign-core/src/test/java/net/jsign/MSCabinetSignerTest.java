/**
 * Copyright 2012 Emmanuel Bourg
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
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.Files;
import java.security.KeyStore;
import java.util.Arrays;
import java.util.List;

import org.apache.commons.compress.utils.SeekableInMemoryByteChannel;
import org.apache.commons.io.FileUtils;
import org.junit.Test;

import net.jsign.mscab.MSCabinetFile;

import static net.jsign.DigestAlgorithm.*;
import static org.junit.Assert.*;

public class MSCabinetSignerTest {

    private static final String PRIVATE_KEY_PASSWORD = "password";
    private static final String ALIAS = "test";

    private KeyStore getKeyStore() throws Exception {
        return new KeyStoreBuilder().keystore("target/test-classes/keystores/keystore.jks").storepass("password").build();
    }

    @Test
    public void testSignSimpleCabinet() throws Exception {
        File sourceFile = new File("target/test-classes/mscab/sample1.cab");
        File targetFile = new File("target/test-classes/mscab/sample1-signed.cab");

        targetFile.getParentFile().mkdirs();

        FileUtils.copyFile(sourceFile, targetFile);

        try (MSCabinetFile cabFile = new MSCabinetFile(targetFile)) {
            AuthenticodeSigner signer = new AuthenticodeSigner(getKeyStore(), ALIAS, PRIVATE_KEY_PASSWORD)
                    .withTimestamping(false);

            signer.sign(cabFile);

            SignatureAssert.assertSigned(cabFile, SHA256);
        }
    }

    @Test
    public void testSignMultiDiskCabinet() throws Exception {
        List<String> disks = Arrays.asList("disk1", "disk2");
        for (String disk : disks) {
            File sourceFile = new File("target/test-classes/mscab/sample2-" + disk + ".cab");
            File targetFile = new File("target/test-classes/mscab/sample2-" + disk + "-signed.cab");

            targetFile.getParentFile().mkdirs();

            FileUtils.copyFile(sourceFile, targetFile);


            AuthenticodeSigner signer = new AuthenticodeSigner(getKeyStore(), ALIAS, PRIVATE_KEY_PASSWORD)
                    .withTimestamping(false);

            try (MSCabinetFile cabFile = new MSCabinetFile(targetFile)) {
                signer.sign(cabFile);
            }

            try (MSCabinetFile cabFile = new MSCabinetFile(targetFile)) {
                SignatureAssert.assertSigned(cabFile, SHA256);
            }
        }
    }

    @Test
    public void testSignCabinetWithPerFolderReserveOnly() throws Exception {
        File sourceFile = new File("target/test-classes/mscab/sample3.cab");
        File targetFile = new File("target/test-classes/mscab/sample3-signed.cab");

        targetFile.getParentFile().mkdirs();

        FileUtils.copyFile(sourceFile, targetFile);

        try (MSCabinetFile cabFile = new MSCabinetFile(targetFile)) {
            AuthenticodeSigner signer = new AuthenticodeSigner(getKeyStore(), ALIAS, PRIVATE_KEY_PASSWORD)
                    .withTimestamping(false);

            signer.sign(cabFile);

            SignatureAssert.assertSigned(cabFile, SHA256);
        }
    }

    @Test
    public void testSignCabinetWithEmptyReserve() throws Exception {
        File sourceFile = new File("target/test-classes/mscab/sample4.cab");
        File targetFile = new File("target/test-classes/mscab/sample4-signed.cab");

        targetFile.getParentFile().mkdirs();

        FileUtils.copyFile(sourceFile, targetFile);

        try (MSCabinetFile cabFile = new MSCabinetFile(targetFile)) {
            AuthenticodeSigner signer = new AuthenticodeSigner(getKeyStore(), ALIAS, PRIVATE_KEY_PASSWORD)
                    .withTimestamping(false);

            signer.sign(cabFile);

            SignatureAssert.assertSigned(cabFile, SHA256);
        }

        // check if the reserve was resized
        try (SeekableByteChannel channel = Files.newByteChannel(targetFile.toPath())) {
            ByteBuffer buffer = ByteBuffer.allocate(40).order(ByteOrder.LITTLE_ENDIAN);
            channel.read(buffer);
            buffer.flip();

            int cbCFHeader = buffer.getShort(36) & 0xFFFF;
            assertEquals("cbCFHeader", 6 * 1024, cbCFHeader);
        }
    }

    @Test
    public void testSignTwice() throws Exception {
        File sourceFile = new File("target/test-classes/mscab/sample1.cab");
        File targetFile = new File("target/test-classes/mscab/sample1-signed-twice.cab");

        targetFile.getParentFile().mkdirs();

        FileUtils.copyFile(sourceFile, targetFile);

        try (MSCabinetFile file = new MSCabinetFile(targetFile)) {
            AuthenticodeSigner signer = new AuthenticodeSigner(getKeyStore(), ALIAS, PRIVATE_KEY_PASSWORD)
                    .withDigestAlgorithm(SHA1)
                    .withTimestamping(true);

            signer.sign(file);

            SignatureAssert.assertSigned(file, SHA1);
            SignatureAssert.assertTimestamped("Invalid timestamp", file.getSignatures().get(0));

            // second signature
            signer.withDigestAlgorithm(SHA256);
            signer.withTimestamping(false);
            signer.sign(file);

            SignatureAssert.assertSigned(file, SHA1, SHA256);
            SignatureAssert.assertTimestamped("Timestamp corrupted after adding the second signature", file.getSignatures().get(0));
        }
    }

    @Test
    public void testSignThreeTimes() throws Exception {
        File sourceFile = new File("target/test-classes/mscab/sample1.cab");
        File targetFile = new File("target/test-classes/mscab/sample1-signed-three-times.cab");

        FileUtils.copyFile(sourceFile, targetFile);

        try (MSCabinetFile file = new MSCabinetFile(targetFile)) {
            AuthenticodeSigner signer = new AuthenticodeSigner(getKeyStore(), ALIAS, PRIVATE_KEY_PASSWORD)
                    .withDigestAlgorithm(SHA1)
                    .withTimestamping(true);

            signer.sign(file);

            SignatureAssert.assertSigned(file, SHA1);
            SignatureAssert.assertTimestamped("Invalid timestamp", file.getSignatures().get(0));

            // second signature
            signer.withDigestAlgorithm(SHA256);
            signer.withTimestamping(false);
            signer.sign(file);

            SignatureAssert.assertSigned(file, SHA1, SHA256);
            SignatureAssert.assertTimestamped("Timestamp corrupted after adding the second signature", file.getSignatures().get(0));

            // third signature
            signer.withDigestAlgorithm(SHA512);
            signer.withTimestamping(false);
            signer.sign(file);

            SignatureAssert.assertSigned(file, SHA1, SHA256, SHA512);
            SignatureAssert.assertTimestamped("Timestamp corrupted after adding the third signature", file.getSignatures().get(0));
        }
    }

    @Test
    public void testReplaceSignature() throws Exception {
        File sourceFile = new File("target/test-classes/mscab/sample1.cab");
        File targetFile = new File("target/test-classes/mscab/sample1-re-signed.cab");

        FileUtils.copyFile(sourceFile, targetFile);

        AuthenticodeSigner signer = new AuthenticodeSigner(getKeyStore(), ALIAS, PRIVATE_KEY_PASSWORD)
                .withDigestAlgorithm(SHA1);

        try (MSCabinetFile file = new MSCabinetFile(targetFile)) {
            signer.sign(file);
        }

        try (MSCabinetFile file = new MSCabinetFile(targetFile)) {
            SignatureAssert.assertSigned(file, SHA1);
        }

        // second signature
        signer.withDigestAlgorithm(SHA256);
        signer.withTimestamping(false);
        signer.withSignaturesReplaced(true);

        try (MSCabinetFile file = new MSCabinetFile(targetFile)) {
            signer.sign(file);
        }

        try (MSCabinetFile file = new MSCabinetFile(targetFile)) {
            SignatureAssert.assertSigned(file, SHA256);
        }
    }

    @Test
    public void testSignInMemory() throws Exception {
        File sourceFile = new File("target/test-classes/mscab/sample1.cab");

        byte[] data = FileUtils.readFileToByteArray(sourceFile);

        SeekableInMemoryByteChannel channel = new SeekableInMemoryByteChannel(data);

        try (MSCabinetFile file = new MSCabinetFile(channel)) {
            AuthenticodeSigner signer = new AuthenticodeSigner(getKeyStore(), ALIAS, PRIVATE_KEY_PASSWORD)
                    .withDigestAlgorithm(SHA512);

            signer.sign(file);
            data = Arrays.copyOf(channel.array(), (int) channel.size());
        }

        try (MSCabinetFile file = new MSCabinetFile(new SeekableInMemoryByteChannel(data))) {
            SignatureAssert.assertSigned(file, SHA512);
        }
    }
}
