/**
 * Copyright 2019 Emmanuel Bourg
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

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.security.KeyStore;

import org.apache.commons.compress.utils.SeekableInMemoryByteChannel;
import org.apache.commons.io.FileUtils;
import org.apache.poi.hpsf.ClassID;
import org.apache.poi.poifs.filesystem.POIFSFileSystem;
import org.junit.Test;

import net.jsign.msi.MSIFile;

import static net.jsign.DigestAlgorithm.*;

public class MSISignerTest {

    private static final String PRIVATE_KEY_PASSWORD = "password";
    private static final String ALIAS = "test";

    private KeyStore getKeyStore() throws Exception {
        return new KeyStoreBuilder().keystore("target/test-classes/keystores/keystore.jks").storepass("password").build();
    }

    @Test
    public void testSign() throws Exception {
        File sourceFile = new File("target/test-classes/minimal.msi");
        File targetFile = new File("target/test-classes/minimal-signed.msi");
        
        FileUtils.copyFile(sourceFile, targetFile);
        
        AuthenticodeSigner signer = new AuthenticodeSigner(getKeyStore(), ALIAS, PRIVATE_KEY_PASSWORD)
                .withTimestamping(false)
                .withProgramName("Hello World")
                .withProgramURL("http://example.com");

        try (MSIFile file = new MSIFile(targetFile)) {
            signer.sign(file);

            SignatureAssert.assertSigned(file, SHA256);
        }
    }

    @Test
    public void testSignTwice() throws Exception {
        File sourceFile = new File("target/test-classes/minimal.msi");
        File targetFile = new File("target/test-classes/minimal-signed-twice.msi");
        
        FileUtils.copyFile(sourceFile, targetFile);
        
        try (MSIFile file = new MSIFile(targetFile)) {
            AuthenticodeSigner signer = new AuthenticodeSigner(getKeyStore(), ALIAS, PRIVATE_KEY_PASSWORD)
                    .withDigestAlgorithm(SHA1)
                    .withTimestamping(true)
                    .withProgramName("Hello World")
                    .withProgramURL("http://example.com");

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
        File sourceFile = new File("target/test-classes/minimal.msi");
        File targetFile = new File("target/test-classes/minimal-signed-three-times.msi");
        
        FileUtils.copyFile(sourceFile, targetFile);
        
        try (MSIFile file = new MSIFile(targetFile)) {
            AuthenticodeSigner signer = new AuthenticodeSigner(getKeyStore(), ALIAS, PRIVATE_KEY_PASSWORD)
                    .withDigestAlgorithm(SHA1)
                    .withTimestamping(true)
                    .withProgramName("Hello World")
                    .withProgramURL("http://example.com");

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
        File sourceFile = new File("target/test-classes/minimal.msi");
        File targetFile = new File("target/test-classes/minimal-re-signed.msi");
        
        FileUtils.copyFile(sourceFile, targetFile);
        
        try (MSIFile file = new MSIFile(targetFile)) {
            AuthenticodeSigner signer = new AuthenticodeSigner(getKeyStore(), ALIAS, PRIVATE_KEY_PASSWORD)
                    .withDigestAlgorithm(SHA1)
                    .withProgramName("Minimal Package")
                    .withProgramURL("http://example.com");

            signer.sign(file);

            SignatureAssert.assertSigned(file, SHA1);

            // second signature
            signer.withDigestAlgorithm(SHA256);
            signer.withTimestamping(false);
            signer.withSignaturesReplaced(true);
            signer.sign(file);

            SignatureAssert.assertSigned(file, SHA256);
        }
    }

    @Test
    public void testReplaceExtendedSignature() throws Exception {
        File sourceFile = new File("target/test-classes/minimal-signed-with-signtool.msi");
        File targetFile = new File("target/test-classes/minimal-signed-with-signtool-re-signed.msi");

        FileUtils.copyFile(sourceFile, targetFile);

        try (MSIFile file = new MSIFile(targetFile)) {
            AuthenticodeSigner signer = new AuthenticodeSigner(getKeyStore(), ALIAS, PRIVATE_KEY_PASSWORD)
                    .withSignaturesReplaced(true)
                    .withDigestAlgorithm(SHA256)
                    .withTimestamping(false)
                    .withProgramName("Minimal Package")
                    .withProgramURL("http://example.com");

            signer.sign(file);

            SignatureAssert.assertSigned(file, SHA256);
        }
    }

    @Test
    public void testSignTwiceWithExtendedSignature() throws Exception {
        File sourceFile = new File("target/test-classes/minimal-signed-with-signtool.msi");
        File targetFile = new File("target/test-classes/minimal-signed-with-signtool-signed-twice.msi");

        FileUtils.copyFile(sourceFile, targetFile);

        try (MSIFile file = new MSIFile(targetFile)) {
            AuthenticodeSigner signer = new AuthenticodeSigner(getKeyStore(), ALIAS, PRIVATE_KEY_PASSWORD)
                    .withDigestAlgorithm(SHA256)
                    .withTimestamping(false);

            signer.sign(file);

            SignatureAssert.assertSigned(file, SHA1, SHA256);
        }
    }

    @Test
    public void testSignInMemory() throws Exception {
        File sourceFile = new File("target/test-classes/minimal.msi");
        
        byte[] data = FileUtils.readFileToByteArray(sourceFile);

        SeekableInMemoryByteChannel channel = new SeekableInMemoryByteChannel(data);

        AuthenticodeSigner signer = new AuthenticodeSigner(getKeyStore(), ALIAS, PRIVATE_KEY_PASSWORD)
                .withDigestAlgorithm(SHA512)
                .withProgramName("Minimal Package")
                .withProgramURL("http://example.com");

        try (MSIFile file = new MSIFile(channel)) {
            signer.sign(file);
            data = channel.array();
        }

        try (MSIFile file = new MSIFile(new SeekableInMemoryByteChannel(data))) {
            SignatureAssert.assertSigned(file, SHA512);
        }
    }

    @Test
    public void testSignPackageWithMiniFATGaps() throws Exception {
        File targetFile = new File("target/test-classes/minimal-with-minifat-gaps.msi");

        // Generate a MSI file with gaps in the mini FAT
        try (POIFSFileSystem fs = new POIFSFileSystem();
             FileOutputStream out = new FileOutputStream(targetFile)) {
            fs.getPropertyTable().getRoot().setStorageClsid(new ClassID("000C108400000000C000000000000046")); // MSI storage class

            // create 3 mini FAT sectors fully allocated
            for (int i = 0; i < 3 * 128; i++) {
                fs.getRoot().createDocument("Entry " + i, new ByteArrayInputStream(new byte[64]));
            }

            // Mini FAT Sector #1: Fully allocated
            // Mini FAT Sector #2: Unallocate 2 mini sectors at the end
            for (int i = 2 * 128 - 2; i < 2 * 128; i++) {
                fs.getRoot().getEntry("Entry " + i).delete();
            }
            // Mini FAT Sector #3: Keep only the 3rd mini sector allocated
            for (int i = 2 * 128; i < 3 * 128; i++) {
                if (i != 2 * 128 + 2) {
                    fs.getRoot().getEntry("Entry " + i).delete();
                }
            }

            fs.writeFilesystem(out);
        }

        AuthenticodeSigner signer = new AuthenticodeSigner(getKeyStore(), ALIAS, PRIVATE_KEY_PASSWORD)
                .withDigestAlgorithm(SHA512)
                .withTimestamping(false);

        try (MSIFile file = new MSIFile(targetFile)) {
            // sign twice to ensure the signature is too large to fit in the mini stream
            signer.sign(file);
            signer.sign(file);

            SignatureAssert.assertSigned(file, SHA512, SHA512);
        }
    }
}
