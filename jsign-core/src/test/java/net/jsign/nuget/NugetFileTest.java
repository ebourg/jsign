/**
 * Copyright 2024 Sebastian Stamm
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

package net.jsign.nuget;

import java.io.File;
import java.io.IOException;
import java.security.KeyStore;

import org.apache.commons.io.FileUtils;
import org.junit.Test;

import net.jsign.AuthenticodeSigner;
import net.jsign.KeyStoreBuilder;
import net.jsign.Signable;
import net.jsign.zip.ZipFile;

import static net.jsign.DigestAlgorithm.*;
import static net.jsign.SignatureAssert.*;
import static org.junit.Assert.*;

public class NugetFileTest {

    @Test
    public void testInvalidPackage() throws Exception {
        File sourceFile = new File("target/test-classes/nuget/minimal.1.0.0.nupkg");
        File targetFile = new File("target/test-classes/nuget/minimal.1.0.0-invalid.nupkg");

        FileUtils.copyFile(sourceFile, targetFile);

        try (ZipFile zip = new ZipFile(targetFile)) {
            zip.renameEntry("[Content_Types].xml", "[Content_Types].old");
        }

        Exception e = assertThrows(IOException.class, () -> new NugetFile(targetFile));
        assertEquals("message", "Invalid NuGet package, [Content_Types].xml is missing", e.getMessage());
    }

    @Test
    public void testGetSignaturesFromUnsignedPackage() throws Exception {
        try (Signable file = new NugetFile(new File("target/test-classes/nuget/minimal.1.0.0.nupkg"))) {
            assertTrue("signature found", file.getSignatures().isEmpty());
        }
    }

    @Test
    public void testRemoveSignature() throws Exception {
        File sourceFile = new File("target/test-classes/nuget/minimal.1.0.0.nupkg");
        File targetFile = new File("target/test-classes/nuget/minimal.1.0.0-signed.nupkg");

        FileUtils.copyFile(sourceFile, targetFile);

        KeyStore keystore = new KeyStoreBuilder().keystore("target/test-classes/keystores/keystore.jks").storepass("password").build();
        AuthenticodeSigner signer = new AuthenticodeSigner(keystore, "test", "password");

        try (Signable file = new NugetFile(targetFile)) {
            file.setSignature(null);
            signer.sign(file);
            assertSigned(file, SHA256);
            file.setSignature(null);
            assertNotSigned(file);
        }
    }
}
