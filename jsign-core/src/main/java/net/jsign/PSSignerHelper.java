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

import java.io.File;
import java.nio.charset.Charset;
import java.security.PrivateKey;
import java.security.cert.Certificate;

/**
 * Helper class to create PSSigner instances with untyped parameters.
 * This is used internally to share the parameter validation logic
 * between the Ant task and the CLI tool.
 */
class PSSignerHelper extends BaseSignerHelper<PSSignerHelper, PSSigner> {
    public static final String PARAM_SCRIPT_ENCODING = "scriptEncoding";

    private Console console;

    private Charset scriptEncoding;

    public PSSignerHelper(Console console, String parameterName) {
        super(parameterName);
        this.console = console;
    }

    public PSSignerHelper scriptEncoding(String scriptEncoding) {
        this.scriptEncoding = Charset.forName(scriptEncoding);
        return this;
    }

    @Override
    public PSSignerHelper param(String key, String value) {
        if (value == null) {
            return this;
        }

        if (PARAM_SCRIPT_ENCODING.equals(key)) {
            return scriptEncoding(value);
        }
        return super.param(key, value);
    }

    @Override
    PSSigner createSigner(Certificate[] chain, PrivateKey privateKey) {
        return new PSSigner(chain, privateKey);
    }

    public PSSigner build() throws SignerException {
        PSSigner signer = super.build();
        if (scriptEncoding != null) {
            signer.withScriptEncoding(scriptEncoding);
        }
        return signer;
    }

    public void sign(File file) throws SignerException {
        PSSigner signer;
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

        try {
            if (console != null) {
                console.info("Adding Authenticode signature to " + file);
            }
            signer.sign(file);
        } catch (Exception e) {
            throw new SignerException("Couldn't sign " + file, e);
        }
    }
}
