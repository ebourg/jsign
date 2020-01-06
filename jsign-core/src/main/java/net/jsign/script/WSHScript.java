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

package net.jsign.script;

import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.MessageDigest;

import static java.nio.charset.StandardCharsets.*;

/**
 * A Windows Script Host file (VB/JS/WSF).
 *
 * @author Emmanuel Bourg
 * @since 3.0
 */
abstract class WSHScript extends SignableScript {

    /**
     * Create a script.
     * The encoding is assumed to be UTF-8.
     */
    public WSHScript() {
        super();
    }

    /**
     * Create a script from the specified file and load its content.
     * If the file has no byte order mark the encoding is assumed to be UTF-8.
     *
     * @param file the script
     * @throws IOException if an I/O error occurs
     */
    public WSHScript(File file) throws IOException {
        super(file);
    }

    /**
     * Create a script from the specified file and load its content.
     *
     * @param file     the script
     * @param encoding the encoding of the script if there is no byte order mark (if null UTF-8 is used by default)
     * @throws IOException if an I/O error occurs
     */
    public WSHScript(File file, Charset encoding) throws IOException {
        super(file, encoding);
    }

    @Override
    boolean isByteOrderMarkSigned() {
        return false;
    }

    @Override
    public byte[] computeDigest(MessageDigest digest) {
        String content = getContentWithoutSignatureBlock();
        digest.update(content.getBytes(UTF_16LE));

        // add the position of the signature block to the hash
        int pos = getSignatureInsertionPoint(content);
        digest.update((byte) pos);
        digest.update((byte) (pos >>> 8));
        digest.update((byte) (pos >>> 16));
        digest.update((byte) (pos >>> 24));

        return digest.digest();
    }
}
