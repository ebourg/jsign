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

import org.bouncycastle.asn1.ASN1Object;

import net.jsign.asn1.authenticode.SpcSipInfo;
import net.jsign.asn1.authenticode.SpcUuid;

/**
 * A Visual Basic script.
 *
 * @author Emmanuel Bourg
 * @since 3.0
 */
public class VBScript extends WSHScript {

    /**
     * Create a Visual Basic script.
     * The encoding is assumed to be UTF-8.
     */
    public VBScript() {
        super();
    }

    /**
     * Create a Visual Basic script from the specified file and load its content.
     * If the file has no byte order mark the encoding is assumed to be UTF-8.
     *
     * @param file the Visual Basic script
     * @throws IOException if an I/O error occurs
     */
    public VBScript(File file) throws IOException {
        super(file);
    }

    /**
     * Create a Visual Basic script from the specified file and load its content.
     *
     * @param file     the Visual Basic script
     * @param encoding the encoding of the script if there is no byte order mark (if null UTF-8 is used by default)
     * @throws IOException if an I/O error occurs
     */
    public VBScript(File file, Charset encoding) throws IOException {
        super(file, encoding);
    }

    @Override
    boolean isUTF8AutoDetected() {
        return false;
    }

    @Override
    String getSignatureStart() {
        return "'' SIG '' Begin signature block";
    }

    @Override
    String getSignatureEnd() {
        return "'' SIG '' End signature block";
    }

    @Override
    String getLineCommentStart() {
        return "'' SIG '' ";
    }

    @Override
    String getLineCommentEnd() {
        return "";
    }

    @Override
    ASN1Object getSpcSipInfo() {
        return new SpcSipInfo(1, new SpcUuid("4EF02916-9927-B54D-8FE5-ACE10F17EBAB"));
    }
}
