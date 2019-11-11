/*
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

import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;

import java.io.File;

/**
 * Maven plugin for signing PE files.
 *
 * @author Björn Kautler
 */
@Mojo(name = "signps")
public class PSSignerMojo extends BaseSignerMojo<PSSignerHelper> {

    /** The encoding of the script to be signed (UTF-8 by default). */
    @Parameter( property = "jsign.scriptEncoding", defaultValue = "UTF-8")
    private String scriptEncoding;

    @Override
    PSSignerHelper createSignerHelper(Console console, String parameterName) {
        return new PSSignerHelper(console, parameterName);
    }

    @Override
    void doExecute(PSSignerHelper helper, File file) throws SignerException {
        helper.scriptEncoding(scriptEncoding);
        helper.sign(file);
    }
}
