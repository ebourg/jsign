/*
 * Copyright 2023 Emmanuel Bourg
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

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStore;
import java.util.zip.GZIPInputStream;

import org.apache.commons.io.IOUtils;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

@RunWith(Parameterized.class)
public class FuzzingTest {

    @Parameters(name = "Fuzzed file #{index}: {0}")
    public static File[] files() {
        return new File("target/test-classes/fuzzer").listFiles();
    }

    private final File file;

    public FuzzingTest(File file) {
        this.file = file;
    }

    @Test
    public void testFuzzing() throws Exception {
        try {
            File extracted = File.createTempFile(file.getName(), "." + getExtension(file));
            extracted.deleteOnExit();

            try (InputStream in = new GZIPInputStream(new BufferedInputStream(new FileInputStream(file)));
                 OutputStream out = new FileOutputStream(extracted)) {
                IOUtils.copy(in, out);
            }

            try (Signable signable = Signable.of(extracted)) {
                KeyStore keystore = new KeyStoreBuilder().keystore("target/test-classes/keystores/keystore-2022.p12").storepass("password").build();
                AuthenticodeSigner signer = new AuthenticodeSigner(keystore, "test", "password").withTimestamping(false);
                signer.sign(signable);
            }
        } catch (IOException | UnsupportedOperationException e) {
            // expected
        }
    }

    private String getExtension(File file) {
        if (file.getName().contains("AuthenticodeAppx")) {
            return "appx";
        } else {
            return "tmp";
        }
    }
}
