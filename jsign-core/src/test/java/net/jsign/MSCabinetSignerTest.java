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
import java.io.FileInputStream;
import java.security.KeyStore;
import java.util.Arrays;
import java.util.List;

import org.apache.commons.compress.utils.SeekableInMemoryByteChannel;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.cms.CMSSignedData;
import org.junit.Test;

import net.jsign.mscab.MSCabinetFile;

import static org.junit.Assert.*;

public class MSCabinetSignerTest {

    private static final String PRIVATE_KEY_PASSWORD = "password";
    private static final String ALIAS = "test";

    private KeyStore getKeyStore() throws Exception {
        KeyStore keystore = KeyStore.getInstance("JKS");
        keystore.load(new FileInputStream("target/test-classes/keystores/keystore.jks"), "password".toCharArray());
        return keystore;
    }

    @Test
    public void testSignSample1() throws Exception {
        File sourceFile = new File("target/test-classes/mscab/sample1.cab");
        File targetFile = new File("target/test-classes/mscab/sample1-signed.cab");

        targetFile.getParentFile().mkdirs();

        FileUtils.copyFile(sourceFile, targetFile);

        MSCabinetFile cabFile = new MSCabinetFile(targetFile);

        AuthenticodeSigner signer = new AuthenticodeSigner(getKeyStore(), ALIAS, PRIVATE_KEY_PASSWORD)
                .withTimestamping(false);

        signer.sign(cabFile);

        cabFile = new MSCabinetFile(targetFile);
        List<CMSSignedData> signatures = cabFile.getSignatures();
        assertNotNull(signatures);
        assertEquals(1, signatures.size());

        CMSSignedData signature = signatures.get(0);

        assertNotNull(signature);
        assertNull(signature.getSignerInfos().iterator().next().getSignedAttributes().get(CMSAttributes.signingTime));
    }

    @Test
    public void testSignSample2() throws Exception {
        List<String> disks = Arrays.asList("disk1", "disk2");
        for (String disk : disks) {
            File sourceFile = new File("target/test-classes/mscab/sample2-" + disk + ".cab");
            File targetFile = new File("target/test-classes/mscab/sample2-" + disk + "-signed.cab");

            targetFile.getParentFile().mkdirs();

            FileUtils.copyFile(sourceFile, targetFile);

            MSCabinetFile cabFile = new MSCabinetFile(targetFile);

            AuthenticodeSigner signer = new AuthenticodeSigner(getKeyStore(), ALIAS, PRIVATE_KEY_PASSWORD)
                    .withTimestamping(false);

            signer.sign(cabFile);

            cabFile = new MSCabinetFile(targetFile);
            List<CMSSignedData> signatures = cabFile.getSignatures();
            assertNotNull(signatures);
            assertEquals(1, signatures.size());

            CMSSignedData signature = signatures.get(0);

            assertNotNull(signature);
            assertNull(signature.getSignerInfos().iterator().next().getSignedAttributes().get(CMSAttributes.signingTime));

            cabFile.close();
        }
    }

    @Test
    public void testSignTwice() throws Exception {
        File sourceFile = new File("target/test-classes/mscab/sample1.cab");
        File targetFile = new File("target/test-classes/mscab/sample1-signed-twice.cab");

        targetFile.getParentFile().mkdirs();

        FileUtils.copyFile(sourceFile, targetFile);

        MSCabinetFile file = new MSCabinetFile(targetFile);

        AuthenticodeSigner signer = new AuthenticodeSigner(getKeyStore(), ALIAS, PRIVATE_KEY_PASSWORD)
                .withDigestAlgorithm(DigestAlgorithm.SHA1)
                .withTimestamping(true);

        signer.sign(file);

        file = new MSCabinetFile(targetFile);

        List<CMSSignedData> signatures = file.getSignatures();
        assertNotNull(signatures);
        assertEquals("number of signatures", 1, signatures.size());

        assertNotNull(signatures.get(0));
        SignatureAssert.assertTimestamped("Invalid timestamp", signatures.get(0));

        // second signature
        signer.withDigestAlgorithm(DigestAlgorithm.SHA256);
        signer.withTimestamping(false);
        signer.sign(file);

        file = new MSCabinetFile(targetFile);
        signatures = file.getSignatures();
        file.close();
        assertNotNull(signatures);
        assertEquals("number of signatures", 2, signatures.size());

        assertNotNull(signatures.get(0));
        SignatureAssert.assertTimestamped("Timestamp corrupted after adding the second signature", signatures.get(0));
    }

    @Test
    public void testSignThreeTimes() throws Exception {
        File sourceFile = new File("target/test-classes/mscab/sample1.cab");
        File targetFile = new File("target/test-classes/mscab/sample1-signed-three-times.cab");

        FileUtils.copyFile(sourceFile, targetFile);

        MSCabinetFile file = new MSCabinetFile(targetFile);

        AuthenticodeSigner signer = new AuthenticodeSigner(getKeyStore(), ALIAS, PRIVATE_KEY_PASSWORD)
                .withDigestAlgorithm(DigestAlgorithm.SHA1)
                .withTimestamping(true);

        signer.sign(file);

        file = new MSCabinetFile(targetFile);

        List<CMSSignedData> signatures = file.getSignatures();
        assertNotNull(signatures);
        assertEquals("number of signatures", 1, signatures.size());

        assertNotNull(signatures.get(0));
        SignatureAssert.assertTimestamped("Invalid timestamp", signatures.get(0));

        // second signature
        signer.withDigestAlgorithm(DigestAlgorithm.SHA256);
        signer.withTimestamping(false);
        signer.sign(file);

        file = new MSCabinetFile(targetFile);
        signatures = file.getSignatures();
        assertNotNull(signatures);
        assertEquals("number of signatures", 2, signatures.size());

        assertNotNull(signatures.get(0));
        SignatureAssert.assertTimestamped("Timestamp corrupted after adding the second signature", signatures.get(0));

        // third signature
        signer.withDigestAlgorithm(DigestAlgorithm.SHA512);
        signer.withTimestamping(false);
        signer.sign(file);

        file = new MSCabinetFile(targetFile);
        signatures = file.getSignatures();
        file.close();
        assertNotNull(signatures);
        assertEquals("number of signatures", 3, signatures.size());

        assertNotNull(signatures.get(0));
        SignatureAssert.assertTimestamped("Timestamp corrupted after adding the third signature", signatures.get(0));
    }

    @Test
    public void testReplaceSignature() throws Exception {
        File sourceFile = new File("target/test-classes/mscab/sample1.cab");
        File targetFile = new File("target/test-classes/mscab/sample1-re-signed.cab");

        FileUtils.copyFile(sourceFile, targetFile);

        MSCabinetFile file = new MSCabinetFile(targetFile);

        AuthenticodeSigner signer = new AuthenticodeSigner(getKeyStore(), ALIAS, PRIVATE_KEY_PASSWORD)
                .withDigestAlgorithm(DigestAlgorithm.SHA1);

        signer.sign(file);

        file = new MSCabinetFile(targetFile);

        List<CMSSignedData> signatures = file.getSignatures();
        assertNotNull(signatures);
        assertEquals("number of signatures", 1, signatures.size());

        assertNotNull(signatures.get(0));

        // second signature
        signer.withDigestAlgorithm(DigestAlgorithm.SHA256);
        signer.withTimestamping(false);
        signer.withSignaturesReplaced(true);
        signer.sign(file);

        file = new MSCabinetFile(targetFile);
        signatures = file.getSignatures();
        file.close();
        assertNotNull(signatures);
        assertEquals("number of signatures", 1, signatures.size());

        assertNotNull(signatures.get(0));

        assertEquals("Digest algorithm", DigestAlgorithm.SHA256.oid, signatures.get(0).getDigestAlgorithmIDs().iterator().next().getAlgorithm());
    }

    @Test
    public void testSignInMemory() throws Exception {
        File sourceFile = new File("target/test-classes/mscab/sample1.cab");

        byte[] data = FileUtils.readFileToByteArray(sourceFile);

        SeekableInMemoryByteChannel channel = new SeekableInMemoryByteChannel(data);

        MSCabinetFile file = new MSCabinetFile(channel);

        AuthenticodeSigner signer = new AuthenticodeSigner(getKeyStore(), ALIAS, PRIVATE_KEY_PASSWORD)
                .withDigestAlgorithm(DigestAlgorithm.SHA512);

        signer.sign(file);

        data = channel.array();
        file = new MSCabinetFile(new SeekableInMemoryByteChannel(data));

        List<CMSSignedData> signatures = file.getSignatures();
        file.close();
        assertNotNull(signatures);
        assertEquals(1, signatures.size());

        CMSSignedData signature = signatures.get(0);

        assertNotNull(signature);
    }
}
