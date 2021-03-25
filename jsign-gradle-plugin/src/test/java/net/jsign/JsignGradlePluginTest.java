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

package net.jsign;

import java.util.HashMap;
import java.util.Map;

import groovy.lang.Closure;
import org.gradle.api.Project;
import org.gradle.api.internal.plugins.DefaultConvention;
import org.gradle.api.plugins.ExtensionContainer;
import org.junit.Assert;
import org.junit.Test;

import static org.mockito.Mockito.*;

public class JsignGradlePluginTest {

    @Test
    public void testRegisterPlugin() {
        Project project = mock(Project.class);
        ExtensionContainer container = new DefaultConvention();
        when(project.getExtensions()).thenReturn(container);

        new JsignGradlePlugin().apply(project);

        Assert.assertNotNull("jsign extension not found", container.getByName("jsign"));
    }

    @Test(expected = SignerException.class)
    public void testCall() {
        Project project = mock(Project.class);
        ExtensionContainer container = new DefaultConvention();
        when(project.getExtensions()).thenReturn(container);

        new JsignGradlePlugin().apply(project);

        Map<String, String> params = new HashMap<>();
        params.put("file", "wineyes.exe");
        params.put("name", "WinEyes");

        Closure closure = (Closure) container.getByName("jsign");
        closure.call(params);
    }
}
