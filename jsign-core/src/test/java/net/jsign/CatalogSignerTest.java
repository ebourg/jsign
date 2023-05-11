/**
 * Copyright 2022 Emmanuel Bourg
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

import org.apache.commons.io.FileUtils;
import org.junit.Test;

import static net.jsign.DigestAlgorithm.*;

public class CatalogSignerTest {

    protected static final String PRIVATE_KEY_PASSWORD = "password";
    protected static final String ALIAS = "test";

    protected KeyStore getKeyStore() throws Exception {
        return new KeyStoreBuilder().keystore("target/test-classes/keystores/keystore.jks").storepass("password").build();
    }

    @Test
    public void testSign() throws Exception {
        File sourceFile = new File("target/test-classes/cat/wineyes.cat");
        File targetFile = new File("target/test-classes/cat/wineyes-signed.cat");

        FileUtils.copyFile(sourceFile, targetFile);

        AuthenticodeSigner signer = new AuthenticodeSigner(getKeyStore(), ALIAS, PRIVATE_KEY_PASSWORD)
                .withTimestamping(false);

        signer.sign(Signable.of(targetFile));

        Signable script = Signable.of(targetFile);

        SignatureAssert.assertSigned(script, SHA256);
    }

    @Test
    public void testSignTwice() throws Exception {
        File sourceFile = new File("target/test-classes/cat/wineyes.cat");
        File targetFile = new File("target/test-classes/cat/wineyes-signed-twice.cat");

        FileUtils.copyFile(sourceFile, targetFile);

        Signable script = Signable.of(targetFile);

        AuthenticodeSigner signer = new AuthenticodeSigner(getKeyStore(), ALIAS, PRIVATE_KEY_PASSWORD)
                .withDigestAlgorithm(SHA1)
                .withTimestamping(true);

        signer.sign(script);

        script = Signable.of(targetFile);

        SignatureAssert.assertSigned(script, SHA1);
        SignatureAssert.assertTimestamped("Invalid timestamp", script.getSignatures().get(0));

        // second signature
        signer.withDigestAlgorithm(SHA256);
        signer.withTimestamping(false);
        signer.sign(script);

        script = Signable.of(targetFile);

        SignatureAssert.assertSigned(script, SHA1, SHA256);
        SignatureAssert.assertTimestamped("Timestamp corrupted after adding the second signature", script.getSignatures().get(0));
    }

    @Test
    public void testSignThreeTimes() throws Exception {
        File sourceFile = new File("target/test-classes/cat/wineyes.cat");
        File targetFile = new File("target/test-classes/cat/wineyes-signed-three-times.cat");

        FileUtils.copyFile(sourceFile, targetFile);

        Signable script = Signable.of(targetFile);

        AuthenticodeSigner signer = new AuthenticodeSigner(getKeyStore(), ALIAS, PRIVATE_KEY_PASSWORD)
                .withDigestAlgorithm(SHA1)
                .withTimestamping(true);

        signer.sign(script);

        script = Signable.of(targetFile);

        SignatureAssert.assertSigned(script, SHA1);
        SignatureAssert.assertTimestamped("Invalid timestamp", script.getSignatures().get(0));

        // second signature
        signer.withDigestAlgorithm(SHA256);
        signer.withTimestamping(false);
        signer.sign(script);

        script = Signable.of(targetFile);

        SignatureAssert.assertSigned(script, SHA1, SHA256);
        SignatureAssert.assertTimestamped("Timestamp corrupted after adding the second signature", script.getSignatures().get(0));

        // third signature
        signer.withDigestAlgorithm(SHA512);
        signer.withTimestamping(false);
        signer.sign(script);

        script = Signable.of(targetFile);

        SignatureAssert.assertSigned(script, SHA1, SHA256, SHA512);
        SignatureAssert.assertTimestamped("Timestamp corrupted after adding the third signature", script.getSignatures().get(0));
    }

    @Test
    public void testReplaceSignature() throws Exception {
        File sourceFile = new File("target/test-classes/cat/wineyes.cat");
        File targetFile = new File("target/test-classes/cat/wineyes-re-signed.cat");

        FileUtils.copyFile(sourceFile, targetFile);

        Signable script = Signable.of(targetFile);

        AuthenticodeSigner signer = new AuthenticodeSigner(getKeyStore(), ALIAS, PRIVATE_KEY_PASSWORD)
                .withDigestAlgorithm(SHA1);

        signer.sign(script);

        script = Signable.of(targetFile);

        SignatureAssert.assertSigned(script, SHA1);

        // second signature
        signer.withDigestAlgorithm(SHA256);
        signer.withTimestamping(false);
        signer.withSignaturesReplaced(true);
        signer.sign(script);

        script = Signable.of(targetFile);

        SignatureAssert.assertSigned(script, SHA256);
    }
}
