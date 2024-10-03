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

import com.cedarsoftware.util.io.JsonReader;
import org.apache.commons.io.IOUtils;
import org.junit.Assume;

public class Azure {

    /**
     * Generates an Azure access token using the CLI: az account get-access-token --resource "https://vault.azure.net"
     */
    public static String getAccessToken() throws IOException, InterruptedException {
        return getAccessToken("https://vault.azure.net");
    }

    /**
     * Generates an Azure access token using the CLI: az account get-access-token --resource &lt;resource&gt;
     */
    public static String getAccessToken(String resource) throws IOException, InterruptedException {
        Process process = null;
        try {
            ProcessBuilder builder = new ProcessBuilder("az.cmd", "account", "get-access-token", "--resource", resource);
            process = builder.start();
            process.waitFor();
            Assume.assumeTrue("Couldn't get Azure API token", process.exitValue() == 0);
        } catch (IOException e) {
            Assume.assumeNoException("Couldn't get Azure API token", e);
        }

        String result = IOUtils.toString(process.getInputStream(), StandardCharsets.ISO_8859_1);
        return (String) JsonReader.jsonToMaps(result).get("accessToken");
    }
}
