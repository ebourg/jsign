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
import java.io.IOException;
import java.security.KeyStore;
import java.util.HashSet;
import java.util.List;

import junit.framework.TestCase;
import net.jsign.pe.PEFile;
import net.jsign.timestamp.AuthenticodeTimestamper;
import net.jsign.timestamp.TimestampingException;
import net.jsign.timestamp.TimestampingMode;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.cms.CMSSignedData;

/**
 * @author Emmanuel Bourg
 * @since 1.0
 */
public class PESignerTest extends TestCase {

    private static String PRIVATE_KEY_PASSWORD = "password";
    private static String ALIAS = "test";

    private KeyStore getKeyStore() throws Exception {
        KeyStore keystore = KeyStore.getInstance("JKS");
        keystore.load(new FileInputStream("target/test-classes/keystore.jks"), "password".toCharArray());
        return keystore;
    }

    public void testSign() throws Exception {
        File sourceFile = new File("target/test-classes/wineyes.exe");
        File targetFile = new File("target/test-classes/wineyes-signed.exe");
        
        FileUtils.copyFile(sourceFile, targetFile);
        
        PEFile peFile = new PEFile(targetFile);
        
        PESigner signer = new PESigner(getKeyStore(), ALIAS, PRIVATE_KEY_PASSWORD)
                .withTimestamping(false)
                .withProgramName("WinEyes")
                .withProgramURL("http://www.steelblue.com/WinEyes");
        
        signer.sign(peFile);
        
        peFile = new PEFile(targetFile);
        List<CMSSignedData> signatures = peFile.getSignatures();
        assertNotNull(signatures);
        assertEquals(1, signatures.size());
        
        CMSSignedData signature = signatures.get(0);
        
        assertNotNull(signature);
    }

    public void testTimestampAuthenticode() throws Exception {
        File sourceFile = new File("target/test-classes/wineyes.exe");
        File targetFile = new File("target/test-classes/wineyes-timestamped-authenticode.exe");

        FileUtils.copyFile(sourceFile, targetFile);
        
        PEFile peFile = new PEFile(targetFile);
        
        PESigner signer = new PESigner(getKeyStore(), ALIAS, PRIVATE_KEY_PASSWORD);
        signer.withDigestAlgorithm(DigestAlgorithm.SHA1);
        signer.withTimestamping(true);
        signer.withTimestampingMode(TimestampingMode.AUTHENTICODE);
        signer.sign(peFile);
        
        peFile = new PEFile(targetFile);
        List<CMSSignedData> signatures = peFile.getSignatures();
        assertNotNull(signatures);
        assertEquals(1, signatures.size());
        
        CMSSignedData signature = signatures.get(0);
        
        assertNotNull(signature);
    }
    
    /**
     * Tests that a custom Timestamper implementation can be provided.
     * @throws Exception 
     */
    public void testWithTimestamper() throws Exception {
        File sourceFile = new File("target/test-classes/wineyes.exe");
        File targetFile = new File("target/test-classes/wineyes-timestamped-authenticode.exe");

        FileUtils.copyFile(sourceFile, targetFile);
        
        PEFile peFile = new PEFile(targetFile);

        final HashSet<Boolean> called = new HashSet<Boolean>();
        
        PESigner signer = new PESigner(getKeyStore(), ALIAS, PRIVATE_KEY_PASSWORD);
        signer.withDigestAlgorithm(DigestAlgorithm.SHA1);
        signer.withTimestamping(true);
        signer.withTimestamper(new AuthenticodeTimestamper() {
            
            @Override
            protected CMSSignedData timestamp(DigestAlgorithm algo, byte[] encryptedDigest) throws IOException, TimestampingException {
                called.add(true);
                return super.timestamp(algo, encryptedDigest);
            }

        });
        signer.sign(peFile);
        
        peFile = new PEFile(targetFile);
        List<CMSSignedData> signatures = peFile.getSignatures();
        assertNotNull(signatures);
        assertEquals(1, signatures.size());
        
        CMSSignedData signature = signatures.get(0);
        
        assertNotNull(signature);
        
        assertTrue("expecting our Timestamper to be used", called.contains(true));
    }

    public void testTimestampRFC3161() throws Exception {
        File sourceFile = new File("target/test-classes/wineyes.exe");
        File targetFile = new File("target/test-classes/wineyes-timestamped-rfc3161.exe");

        FileUtils.copyFile(sourceFile, targetFile);
        
        PEFile peFile = new PEFile(targetFile);
        
        PESigner signer = new PESigner(getKeyStore(), ALIAS, PRIVATE_KEY_PASSWORD);
        signer.withDigestAlgorithm(DigestAlgorithm.SHA256);
        signer.withTimestamping(true);
        signer.withTimestampingMode(TimestampingMode.RFC3161);
        signer.sign(peFile);
        
        peFile = new PEFile(targetFile);
        List<CMSSignedData> signatures = peFile.getSignatures();
        assertNotNull(signatures);
        assertEquals(1, signatures.size());
        
        CMSSignedData signature = signatures.get(0);
        
        assertNotNull(signature);
    }
}
