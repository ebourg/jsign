/*
 * Copyright 2025 Emmanuel Bourg
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
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import groovy.lang.Closure;
import org.gradle.api.Project;
import org.gradle.api.file.FileCollection;

/**
 * Jsign extension method for Gradle.
 *
 * @since 7.2
 */
public class JsignExtension extends Closure<Void> {

    private final Project project;

    public JsignExtension(Project project) {
        super(null);
        this.project = project;
    }

    public void doCall(Map<String, ?> params) throws SignerException {
        String file = (String) params.get("file");
        params.remove("file");

        FileCollection fileset = null;
        if (params.containsKey("fileset")) {
            fileset = project.files(params.get("fileset"));
            params.remove("fileset");
        }

        boolean quiet = "true".equals(params.get("quiet"));
        Logger.getLogger("net.jsign").setLevel(quiet ? Level.WARNING : Level.ALL);

        SignerHelper helper = new SignerHelper("property");
        helper.setBaseDir(project.getProjectDir());
        for (Map.Entry<String, ?> param : params.entrySet()) {
            helper.param(param.getKey(), (String) param.getValue());
        }

        if (fileset != null && !fileset.isEmpty()) {
            for (File f : fileset) {
                helper.execute(f);
            }
        } else {
            helper.execute(file);
        }
    }

    public void doCall(kotlin.Pair<String, ?>... pairs) throws SignerException {
        Map<String, Object> params = new HashMap<>();
        for (kotlin.Pair<String, ?> pair : pairs) {
            params.put(pair.getFirst(), pair.getSecond());
        }
        doCall(params);
    }
}
