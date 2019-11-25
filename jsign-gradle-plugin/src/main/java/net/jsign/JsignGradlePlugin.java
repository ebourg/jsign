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
import java.util.Map;

import groovy.lang.Closure;
import org.gradle.api.Plugin;
import org.gradle.api.Project;

/**
 * Gradle plugin registering the jsign extension method with the project.
 *
 * @author Emmanuel Bourg
 * @since 2.0
 */
public class JsignGradlePlugin implements Plugin<Project> {

    @Override
    public void apply(final Project project) {
        project.getExtensions().add("jsign", new Closure(null) {
            public void doCall(Map<String, String> params) throws SignerException {
                String file = params.get("file");
                params.remove("file");
                
                SignerHelper helper = new SignerHelper(new GradleConsole(project.getLogger()), "property");
                for (Map.Entry<String, String> param : params.entrySet()) {
                    helper.param(param.getKey(), param.getValue());
                }
                helper.sign(new File(file));
            }
        });
    }
}
