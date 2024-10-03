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

import org.junit.Assume;

/**
 * https://digicert.github.io/snowbird-doc/#/administration-guides/secure-software-manager/environment-variables
 */
public class DigiCertONE {
    
    public static String getApiKey() {
        return getVariable("SM_API_KEY");
    }

    public static String getClientCertificateFile() {
        return getVariable("SM_CLIENT_CERT_FILE");
    }

    public static String getClientCertificatePassword() {
        return getVariable("SM_CLIENT_CERT_PASSWORD");
    }

    private static String getVariable(String name) {
        String value = System.getenv(name);
        Assume.assumeTrue("Environment variable " + name + " is not set", value != null);
        return value;
    }
}
