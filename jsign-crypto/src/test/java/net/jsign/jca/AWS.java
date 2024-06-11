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

package net.jsign.jca;

import org.junit.Assume;

/**
 * https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-quickstart.html#cli-configure-quickstart-precedence
 */
public class AWS {

    public static String getAccessKey() {
        return getVariable("AWS_ACCESS_KEY_ID");
    }

    public static String getSecretKey() {
        return getVariable("AWS_SECRET_ACCESS_KEY");
    }

    private static String getVariable(String name) {
        String value = System.getenv(name);
        Assume.assumeTrue("Environment variable " + name + " is not set", value != null);
        return value;
    }
}
