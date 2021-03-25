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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.util.List;

import org.apache.commons.io.ByteOrderMark;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.cms.CMSSignedData;
import org.junit.Ignore;
import org.junit.Test;

import static org.junit.Assert.*;

public abstract class ScriptSignerTest {

    protected static final String PRIVATE_KEY_PASSWORD = "password";
    protected static final String ALIAS = "test";

    protected abstract String getFileExtension();
    
    protected KeyStore getKeyStore() throws Exception {
        KeyStore keystore = KeyStore.getInstance("JKS");
        keystore.load(new FileInputStream("target/test-classes/keystores/keystore.jks"), "password".toCharArray());
        return keystore;
    }

    @Test
    public void testSign() throws Exception {
        File sourceFile = new File("target/test-classes/hello-world." + getFileExtension());
        File targetFile = new File("target/test-classes/hello-world-signed." + getFileExtension());
        
        FileUtils.copyFile(sourceFile, targetFile);
        
        AuthenticodeSigner signer = new AuthenticodeSigner(getKeyStore(), ALIAS, PRIVATE_KEY_PASSWORD)
                .withTimestamping(false)
                .withProgramName("Hello World")
                .withProgramURL("http://example.com");
        
        signer.sign(Signable.of(targetFile));

        Signable script = Signable.of(targetFile);
        
        List<CMSSignedData> signatures = script.getSignatures();
        assertNotNull(signatures);
        assertEquals(1, signatures.size());
        
        CMSSignedData signature = signatures.get(0);
        
        assertNotNull(signature);
    }

    @Test
    public void testSignTwice() throws Exception {
        File sourceFile = new File("target/test-classes/hello-world." + getFileExtension());
        File targetFile = new File("target/test-classes/hello-world-signed-twice." + getFileExtension());
        
        FileUtils.copyFile(sourceFile, targetFile);
        
        Signable script = Signable.of(targetFile);
        
        AuthenticodeSigner signer = new AuthenticodeSigner(getKeyStore(), ALIAS, PRIVATE_KEY_PASSWORD)
                .withDigestAlgorithm(DigestAlgorithm.SHA1)
                .withTimestamping(true)
                .withProgramName("Hello World")
                .withProgramURL("http://example.com");
        
        signer.sign(script);
        
        script = Signable.of(targetFile);
        
        List<CMSSignedData> signatures = script.getSignatures();
        assertNotNull(signatures);
        assertEquals("number of signatures", 1, signatures.size());
        
        assertNotNull(signatures.get(0));
        SignatureAssert.assertTimestamped("Invalid timestamp", signatures.get(0));
        
        // second signature
        signer.withDigestAlgorithm(DigestAlgorithm.SHA256);
        signer.withTimestamping(false);
        signer.sign(script);
        
        script = Signable.of(targetFile);
        signatures = script.getSignatures();
        assertNotNull(signatures);
        assertEquals("number of signatures", 2, signatures.size());
        
        assertNotNull(signatures.get(0));
        SignatureAssert.assertTimestamped("Timestamp corrupted after adding the second signature", signatures.get(0));
    }

    @Test
    public void testSignThreeTimes() throws Exception {
        File sourceFile = new File("target/test-classes/hello-world." + getFileExtension());
        File targetFile = new File("target/test-classes/hello-world-signed-three-times." + getFileExtension());
        
        FileUtils.copyFile(sourceFile, targetFile);
        
        Signable script = Signable.of(targetFile);
        
        AuthenticodeSigner signer = new AuthenticodeSigner(getKeyStore(), ALIAS, PRIVATE_KEY_PASSWORD)
                .withDigestAlgorithm(DigestAlgorithm.SHA1)
                .withTimestamping(true)
                .withProgramName("Hello World")
                .withProgramURL("http://example.com");
        
        signer.sign(script);
        
        script = Signable.of(targetFile);
        
        List<CMSSignedData> signatures = script.getSignatures();
        assertNotNull(signatures);
        assertEquals("number of signatures", 1, signatures.size());
        
        assertNotNull(signatures.get(0));
        SignatureAssert.assertTimestamped("Invalid timestamp", signatures.get(0));
        
        // second signature
        signer.withDigestAlgorithm(DigestAlgorithm.SHA256);
        signer.withTimestamping(false);
        signer.sign(script);
        
        script = Signable.of(targetFile);
        signatures = script.getSignatures();
        assertNotNull(signatures);
        assertEquals("number of signatures", 2, signatures.size());
        
        assertNotNull(signatures.get(0));
        SignatureAssert.assertTimestamped("Timestamp corrupted after adding the second signature", signatures.get(0));
        
        // third signature
        signer.withDigestAlgorithm(DigestAlgorithm.SHA512);
        signer.withTimestamping(false);
        signer.sign(script);
        
        script = Signable.of(targetFile);
        signatures = script.getSignatures();
        assertNotNull(signatures);
        assertEquals("number of signatures", 3, signatures.size());
        
        assertNotNull(signatures.get(0));
        SignatureAssert.assertTimestamped("Timestamp corrupted after adding the third signature", signatures.get(0));
    }

    @Test
    public void testReplaceSignature() throws Exception {
        File sourceFile = new File("target/test-classes/hello-world." + getFileExtension());
        File targetFile = new File("target/test-classes/hello-world-re-signed." + getFileExtension());
        
        FileUtils.copyFile(sourceFile, targetFile);
        
        Signable script = Signable.of(targetFile);
        
        AuthenticodeSigner signer = new AuthenticodeSigner(getKeyStore(), ALIAS, PRIVATE_KEY_PASSWORD)
                .withDigestAlgorithm(DigestAlgorithm.SHA1)
                .withProgramName("Hello World")
                .withProgramURL("http://example.com");
        
        signer.sign(script);
        
        script = Signable.of(targetFile);
        
        List<CMSSignedData> signatures = script.getSignatures();
        assertNotNull(signatures);
        assertEquals("number of signatures", 1, signatures.size());
        
        assertNotNull(signatures.get(0));
        
        // second signature
        signer.withDigestAlgorithm(DigestAlgorithm.SHA256);
        signer.withTimestamping(false);
        signer.withSignaturesReplaced(true);
        signer.sign(script);
        
        script = Signable.of(targetFile);
        signatures = script.getSignatures();
        assertNotNull(signatures);
        assertEquals("number of signatures", 1, signatures.size());
        
        assertNotNull(signatures.get(0));
        
        assertEquals("Digest algorithm", DigestAlgorithm.SHA256.oid, signatures.get(0).getDigestAlgorithmIDs().iterator().next().getAlgorithm());
    }

    public void testSignWithBOM(ByteOrderMark bom) throws Exception {
        Charset encoding = Charset.forName(bom.getCharsetName());
        String encodingName = encoding.name().toLowerCase().replace("-", "");
        
        // create the test file with the bom
        File sourceFile = new File("target/test-classes/hello-world-" + encodingName + "-with-bom." + getFileExtension());
        FileOutputStream out = new FileOutputStream(sourceFile);
        out.write(bom.getBytes());
        out.write(FileUtils.readFileToString(new File("target/test-classes/hello-world." + getFileExtension()), StandardCharsets.UTF_8).getBytes(encoding));
        out.flush();
        out.close();
        
        File targetFile = new File("target/test-classes/hello-world-" + encodingName + "-with-bom-signed." + getFileExtension());
        
        FileUtils.copyFile(sourceFile, targetFile);
        
        // sign
        AuthenticodeSigner signer = new AuthenticodeSigner(getKeyStore(), ALIAS, PRIVATE_KEY_PASSWORD)
                .withDigestAlgorithm(DigestAlgorithm.SHA1)
                .withTimestamping(false)
                .withProgramName("Hello World")
                .withProgramURL("http://example.com");
        
        signer.sign(Signable.of(targetFile, encoding));
        
        Signable script = Signable.of(targetFile, encoding);
        
        List<CMSSignedData> signatures = script.getSignatures();
        assertNotNull(signatures);
        assertEquals(1, signatures.size());
        
        CMSSignedData signature = signatures.get(0);
        
        assertNotNull(signature);
    }

    @Test
    public void testSignUTF8WithBOM() throws Exception {
        testSignWithBOM(ByteOrderMark.UTF_8);
    }

    @Test
    public void testSignUTF16LEWithBOM() throws Exception {
        testSignWithBOM(ByteOrderMark.UTF_16LE);
    }

    @Test
    public void testSignUTF16BEWithBOM() throws Exception {
        testSignWithBOM(ByteOrderMark.UTF_16BE);
    }

    @Test
    @Ignore("Not properly handled by Windows")
    public void testSignUTF32LEWithBOM() throws Exception {
        testSignWithBOM(ByteOrderMark.UTF_32LE);
    }

    @Test
    @Ignore("Not properly handled by Windows")
    public void testSignUTF32BEWithBOM() throws Exception {
        testSignWithBOM(ByteOrderMark.UTF_32BE);
    }

    @Test
    public void testSignLatin1() throws Exception {
        Charset encoding = StandardCharsets.ISO_8859_1;
        String encodingName = "latin1";
        
        // create the test file with the bom
        String content = FileUtils.readFileToString(new File("target/test-classes/hello-world." + getFileExtension()), StandardCharsets.UTF_8);
        content = content.replace("Hello World", "Halló heimur");
        content = content.replace("utf-8", "iso-8859-1");
        
        File sourceFile = new File("target/test-classes/hello-world-" + encodingName + "." + getFileExtension());
        FileOutputStream out = new FileOutputStream(sourceFile);
        out.write(content.getBytes(encoding));
        out.flush();
        out.close();
        
        File targetFile = new File("target/test-classes/hello-world-" + encodingName + "-signed." + getFileExtension());
        
        FileUtils.copyFile(sourceFile, targetFile);
        
        // sign
        AuthenticodeSigner signer = new AuthenticodeSigner(getKeyStore(), ALIAS, PRIVATE_KEY_PASSWORD)
                .withDigestAlgorithm(DigestAlgorithm.SHA1)
                .withTimestamping(false)
                .withProgramName("Hello World")
                .withProgramURL("http://example.com");
        
        signer.sign(Signable.of(targetFile, encoding));
        
        Signable script = Signable.of(targetFile, encoding);
        
        List<CMSSignedData> signatures = script.getSignatures();
        assertNotNull(signatures);
        assertEquals(1, signatures.size());
        
        CMSSignedData signature = signatures.get(0);
        
        assertNotNull(signature);
    }

    @Test
    public void testSignUTF8() throws Exception {
        Charset encoding = StandardCharsets.UTF_8;
        String encodingName = "utf8";
        
        // create the test file with the bom
        String content = FileUtils.readFileToString(new File("target/test-classes/hello-world." + getFileExtension()), StandardCharsets.UTF_8);
        content = content.replace("Hello World", "Halló heimur");
        
        File sourceFile = new File("target/test-classes/hello-world-" + encodingName + "." + getFileExtension());
        FileOutputStream out = new FileOutputStream(sourceFile);
        out.write(content.getBytes(encoding));
        out.flush();
        out.close();
        
        File targetFile = new File("target/test-classes/hello-world-" + encodingName + "-signed." + getFileExtension());
        
        FileUtils.copyFile(sourceFile, targetFile);
        
        // sign
        AuthenticodeSigner signer = new AuthenticodeSigner(getKeyStore(), ALIAS, PRIVATE_KEY_PASSWORD)
                .withDigestAlgorithm(DigestAlgorithm.SHA1)
                .withTimestamping(false)
                .withProgramName("Hello World")
                .withProgramURL("http://example.com");
        
        signer.sign(Signable.of(targetFile, encoding));
        
        Signable script = Signable.of(targetFile, encoding);
        
        List<CMSSignedData> signatures = script.getSignatures();
        assertNotNull(signatures);
        assertEquals(1, signatures.size());
        
        CMSSignedData signature = signatures.get(0);
        
        assertNotNull(signature);
    }

    @Test
    public void testSignUTF16LE() throws Exception {
        Charset encoding = StandardCharsets.UTF_16LE;
        String encodingName = "utf16le";
        
        // create the test file with the bom
        String content = FileUtils.readFileToString(new File("target/test-classes/hello-world." + getFileExtension()), StandardCharsets.UTF_8);
        content = content.replace("Hello World", "Halló heimur");
        
        File sourceFile = new File("target/test-classes/hello-world-" + encodingName + "." + getFileExtension());
        FileOutputStream out = new FileOutputStream(sourceFile);
        out.write(content.getBytes(encoding));
        out.flush();
        out.close();
        
        File targetFile = new File("target/test-classes/hello-world-" + encodingName + "-signed." + getFileExtension());
        
        FileUtils.copyFile(sourceFile, targetFile);
        
        // sign
        AuthenticodeSigner signer = new AuthenticodeSigner(getKeyStore(), ALIAS, PRIVATE_KEY_PASSWORD)
                .withDigestAlgorithm(DigestAlgorithm.SHA1)
                .withTimestamping(false)
                .withProgramName("Hello World")
                .withProgramURL("http://example.com");
        
        signer.sign(Signable.of(targetFile, encoding));
        
        Signable script = Signable.of(targetFile, encoding);
        
        List<CMSSignedData> signatures = script.getSignatures();
        assertNotNull(signatures);
        assertEquals(1, signatures.size());
        
        CMSSignedData signature = signatures.get(0);
        
        assertNotNull(signature);
    }
}
