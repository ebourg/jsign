/**
 * Copyright 2021 Emmanuel Bourg
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

package net.jsign.jca;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.apache.commons.io.IOUtils;
import org.junit.Assume;

public class GoogleCloud {

    /**
     * Generates a Google Cloud access token using the CLI: gcloud auth print-access-token
     */
    public static String getAccessToken() throws IOException, InterruptedException {
        Process process = null;
        try {
            ProcessBuilder builder = new ProcessBuilder("C:/Program Files (x86)/Google/Cloud SDK/google-cloud-sdk/bin/gcloud.cmd", "auth", "print-access-token");
            process = builder.start();
            process.waitFor();
            Assume.assumeTrue("Couldn't get Google Cloud API token", process.exitValue() == 0);
        } catch (IOException e) {
            Assume.assumeNoException("Couldn't get Google Cloud API token", e);
        }

        return IOUtils.toString(process.getInputStream(), StandardCharsets.ISO_8859_1).trim();
    }
}
