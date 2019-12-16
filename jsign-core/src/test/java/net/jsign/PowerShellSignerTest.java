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

import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.cms.CMSSignedData;
import org.junit.Test;

import net.jsign.script.PowerShellScript;

import static org.junit.Assert.*;

public class PowerShellSignerTest extends ScriptSignerTest {

    @Override
    protected String getFileExtension() {
        return "ps1";
    }

    @Test
    public void testSignInMemory() throws Exception {
        PowerShellScript script = new PowerShellScript();
        script.setContent("write-host \"Hello World!\"\n");
        
        AuthenticodeSigner signer = new AuthenticodeSigner(getKeyStore(), ALIAS, PRIVATE_KEY_PASSWORD)
                .withDigestAlgorithm(DigestAlgorithm.SHA512)
                .withProgramName("Hello World")
                .withProgramURL("http://example.com");
        
        signer.sign(script);
        script.save();
        
        PowerShellScript script2 = new PowerShellScript();
        script2.setContent(script.getContent());
        
        List<CMSSignedData> signatures = script2.getSignatures();
        assertNotNull(signatures);
        assertEquals(1, signatures.size());
        
        CMSSignedData signature = signatures.get(0);
        
        assertNotNull(signature);
    }

    @Test
    public void testSignScriptWithMessedEOL() throws Exception {
        PowerShellScript script = new PowerShellScript();
        script.setContent("write-host \"Hello World!\"\n");
        
        AuthenticodeSigner signer = new AuthenticodeSigner(getKeyStore(), ALIAS, PRIVATE_KEY_PASSWORD)
                .withDigestAlgorithm(DigestAlgorithm.SHA1)
                .withTimestamping(false);
        
        signer.sign(script);

        List<CMSSignedData> signatures = script.getSignatures();
        assertNotNull(signatures);
        assertEquals(1, signatures.size());
        
        // convert the file from CRLF to LF, the signature should become unavailable
        script.setContent(script.getContent().replace("\r\n", "\n"));
        
        signatures = script.getSignatures();
        assertNotNull(signatures);
        assertEquals(0, signatures.size());
        
        // sign again, the previous invalid signature block should be removed (as done by Set-AuthenticodeSignature cmdlet)
        signer.sign(script);
        
        signatures = script.getSignatures();
        assertNotNull(signatures);
        assertEquals(1, signatures.size());
        
        assertEquals("Number of signature blocks", 1, StringUtils.countMatches(script.getContent(), "Begin signature block"));
    }
}
