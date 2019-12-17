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

package net.jsign.script;

import java.io.File;

import org.junit.Test;

import static org.junit.Assert.*;

public class PowerShellScriptTest extends ScriptTest {

    @Override
    protected String getFileExtension() {
        return "ps1";
    }

    @Override
    protected SignableScript createScript() {
        return new PowerShellScript();
    }

    @Test
    public void testGetContent() throws Exception {
        PowerShellScript script = new PowerShellScript(new File("target/test-classes/hello-world.ps1"));
        
        assertNotNull("content null", script.getContent());
        assertEquals("content", "write-host \"Hello World!\"\r\n", script.getContent());
    }
    
    @Test
    public void testGetSignature() throws Exception {
        PowerShellScript script = new PowerShellScript(new File("target/test-classes/hello-world.ps1"));
        
        assertTrue("signature found", script.getSignatures().isEmpty());
    }
}
