/**
 * Copyright 2024 Emmanuel Bourg
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

package net.jsign.spi;

import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;

import org.kohsuke.MetaInfServices;

import net.jsign.Signable;
import net.jsign.script.VBScript;

/**
 * {@link SignableProvider} for VBScript files.
 *
 * @since 7.0
 */
@MetaInfServices(SignableProvider.class)
public class VBScriptSignableProvider extends ExtensionBasedSignableProvider {

    public VBScriptSignableProvider() {
        super("vbs", "vbe");
    }

    @Override
    public Signable create(File file, Charset encoding) throws IOException {
        return new VBScript(file, encoding);
    }
}
