/*
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

package net.jsign.script;

import java.io.File;
import java.security.KeyStore;

import org.apache.commons.io.FileUtils;
import org.junit.Test;

import net.jsign.AuthenticodeSigner;
import net.jsign.KeyStoreBuilder;
import net.jsign.Signable;
import net.jsign.SignatureAssert;

import static net.jsign.DigestAlgorithm.*;
import static net.jsign.SignatureAssert.*;
import static org.junit.Assert.*;

public abstract class ScriptTest {

    protected static final String PRIVATE_KEY_PASSWORD = "password";
    protected static final String ALIAS = "test";

    protected abstract String getFileExtension();

    protected abstract SignableScript createScript();

    protected KeyStore getKeyStore() throws Exception {
        return new KeyStoreBuilder().keystore("target/test-classes/keystores/keystore.jks").storepass("password").build();
    }

    private AuthenticodeSigner getSigner() throws Exception {
        return new AuthenticodeSigner(getKeyStore(), ALIAS, PRIVATE_KEY_PASSWORD)
                        .withDigestAlgorithm(SHA1)
                        .withProgramName("Hello World")
                        .withProgramURL("http://example.com");
    }

    @Test
    public void testGetContentWithoutSignature() throws Exception {
        File sourceFile = new File("target/test-classes/hello-world." + getFileExtension());
        String content = FileUtils.readFileToString(sourceFile, "ISO-8859-1");

        SignableScript script = createScript();
        script.setContent(content);
        getSigner().sign(script);
        
        SignatureAssert.assertSigned(script, SHA1);
        
        assertEquals("script with the signature removed", content, script.getContentWithoutSignatureBlock());
    }

    @Test
    public void testRemoveSignature() throws Exception {
        File sourceFile = new File("target/test-classes/hello-world." + getFileExtension());
        File targetFile = new File("target/test-classes/hello-world-unsigned." + getFileExtension());

        FileUtils.copyFile(sourceFile, targetFile);

        KeyStore keystore = new KeyStoreBuilder().keystore("target/test-classes/keystores/keystore.jks").storepass("password").build();
        AuthenticodeSigner signer = new AuthenticodeSigner(keystore, "test", "password").withTimestamping(false);

        try (Signable script = Signable.of(targetFile)) {
            script.setSignature(null);
            signer.sign(script);
            assertSigned(script, SHA256);
            script.setSignature(null);
            script.save();
            assertNotSigned(script);
        }
    }
}
