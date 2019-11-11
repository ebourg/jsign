/*
 * Copyright 2017 Emmanuel Bourg and contributors
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

import net.jsign.pe.PEFile;

import java.io.File;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.cert.Certificate;

/**
 * Helper class to create PESigner instances with untyped parameters.
 * This is used internally to share the parameter validation logic
 * between the Ant task and the CLI tool.
 *
 * @since 2.0
 */
class PESignerHelper extends BaseSignerHelper<PESignerHelper, PESigner> {
    public static final String PARAM_REPLACE = "replace";

    private Console console;

    private boolean replace;

    public PESignerHelper(Console console, String parameterName) {
        super(parameterName);
        this.console = console;
    }

    public PESignerHelper replace(boolean replace) {
        this.replace = replace;
        return this;
    }

    @Override
    public PESignerHelper param(String key, String value) {
        if (value == null) {
            return this;
        }

        if (PARAM_REPLACE.equals(key)) {
            return replace("true".equalsIgnoreCase(value));
        }
        return super.param(key, value);
    }

    @Override
    PESigner createSigner(Certificate[] chain, PrivateKey privateKey) {
        return new PESigner(chain, privateKey);
    }

    public PESigner build() throws SignerException {
        return super.build().withSignaturesReplaced(replace);
    }

    public void sign(File file) throws SignerException {
        PESigner signer;
        try {
            signer = build();
        } catch (SignerException e) {
            throw e;
        } catch (Exception e) {
            throw new SignerException("Couldn't sign " + file, e);
        }

        if (file == null) {
            throw new SignerException("file must be set");
        }
        if (!file.exists()) {
            throw new SignerException("The file " + file + " couldn't be found");
        }

        PEFile peFile;
        try {
            peFile = new PEFile(file);
        } catch (IOException e) {
            throw new SignerException("Couldn't open the executable file " + file, e);
        }

        try {
            if (console != null) {
                console.info("Adding Authenticode signature to " + file);
            }
            signer.sign(peFile);
        } catch (Exception e) {
            throw new SignerException("Couldn't sign " + file, e);
        } finally {
            try {
                peFile.close();
            } catch (IOException e) {
                if (console != null) {
                    console.warn("Couldn't close " + file, e);
                }
            }
        }
    }
}
