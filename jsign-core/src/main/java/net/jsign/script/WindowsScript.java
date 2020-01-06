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
 * A Windows script file (<code>.wsf</code>).
 *
 * @author Emmanuel Bourg
 * @since 3.0
 */
public class WindowsScript extends WSHScript {

    /**
     * Create a Windows script.
     * The encoding is assumed to be UTF-8.
     */
    public WindowsScript() {
        super();
    }

    /**
     * Create a Windows script from the specified file and load its content.
     * If the file has no byte order mark the encoding is assumed to be UTF-8.
     *
     * @param file the Windows script
     * @throws IOException if an I/O error occurs
     */
    public WindowsScript(File file) throws IOException {
        super(file);
    }

    /**
     * Create a Windows script from the specified file and load its content.
     *
     * @param file     the Windows script
     * @param encoding the encoding of the script if there is no byte order mark (if null UTF-8 is used by default)
     * @throws IOException if an I/O error occurs
     */
    public WindowsScript(File file, Charset encoding) throws IOException {
        super(file, encoding);
    }

    @Override
    String getSignatureStart() {
        return "<signature>";
    }

    @Override
    String getSignatureEnd() {
        return "</signature>";
    }

    @Override
    String getLineCommentStart() {
        return "** SIG ** ";
    }

    @Override
    String getLineCommentEnd() {
        return "";
    }

    @Override
    protected int getSignatureInsertionPoint(String content) {
        return content.lastIndexOf("</job>");
    }

    @Override
    ASN1Object getSpcSipInfo() {
        return new SpcSipInfo(1, new SpcUuid("7005611A-CE38-D411-A2A3-00104BD35090"));
    }
}
