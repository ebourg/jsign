/*
 * Copyright 2012 Björn Kautler
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

/**
 * Ant task for signing PowerShell scripts.
 *
 * @author Björn Kautler
 */
public class PSSignerTask extends BaseSignerTask<PSSignerHelper> {

    /**
     * The encoding of the script to be signed (UTF-8 by default).
     */
    private String scriptEncoding = "UTF-8";

    public void setScriptEncoding(String scriptEncoding) {
        this.scriptEncoding = scriptEncoding;
    }

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
