/*
 * Copyright 2017 Emmanuel Bourg
 * Copyright 2019 Björn Kautler
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

import groovy.lang.Closure;
import org.gradle.api.Plugin;
import org.gradle.api.Project;

import java.io.File;
import java.util.Map;

/**
 * Gradle plugin registering the signexe and signps extension methods with the project.
 *
 * @author Emmanuel Bourg
 * @since 2.0
 */
public class PESignerGradlePlugin implements Plugin<Project> {

    @Override
    public void apply(final Project project) {
        project.getExtensions().add("signexe", new Closure(null) {
            public void doCall(Map<String, String> params) throws SignerException {
                String file = params.get("file");
                params.remove("file");

                PESignerHelper helper = new PESignerHelper(new GradleConsole(project.getLogger()), "property");
                for (Map.Entry<String, String> param : params.entrySet()) {
                    helper.param(param.getKey(), param.getValue());
                }
                helper.sign(new File(file));
            }
        });

        project.getExtensions().add("signps", new Closure(null) {
            public void doCall(Map<String, String> params) throws SignerException {
                String file = params.get("file");
                params.remove("file");

                PSSignerHelper helper = new PSSignerHelper(new GradleConsole(project.getLogger()), "property");
                for (Map.Entry<String, String> param : params.entrySet()) {
                    helper.param(param.getKey(), param.getValue());
                }
                helper.sign(new File(file));
            }
        });
    }
}
