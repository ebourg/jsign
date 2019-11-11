/*
 * Copyright 2012 Emmanuel Bourg
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

import java.io.File;

/**
 * Ant task for signing executable files.
 *
 * @author Emmanuel Bourg
 * @since 1.0
 */
public class PESignerTask extends BaseSignerTask<PESignerHelper> {

    /** Tells if previous signatures should be replaced */
    private boolean replace;

    public void setReplace(boolean replace) {
        this.replace = replace;
    }

    @Override
    PESignerHelper createSignerHelper(Console console, String parameterName) {
        return new PESignerHelper(console, parameterName);
    }

    @Override
    void doExecute(PESignerHelper helper, File file) throws SignerException {
        helper.replace(replace);
        helper.sign(file);
    }
}
