/**
 * Copyright 2017 Emmanuel Bourg
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

import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugin.testing.AbstractMojoTestCase;

public class JsignMojoTest extends AbstractMojoTestCase {

    public void testMojo() throws Exception {
        File pom = getTestFile("target/test-classes/test-pom.xml");
        assertNotNull("null pom", pom);
        assertTrue("pom not found", pom.exists());

        JsignMojo mojo = (JsignMojo) lookupMojo("sign", pom);
        assertNotNull("plugin not found", mojo);
        try {
            mojo.execute();
        } catch (MojoFailureException e) {
            // expected
            assertEquals("keystore element, or keyfile and certfile elements must be set", e.getMessage());
        }
    }
}
