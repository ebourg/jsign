/**
 * Copyright 2019 Emmanuel Bourg and contributors
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
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.util.List;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.cms.CMSSignedData;

import net.jsign.msi.MSIFile;
import net.jsign.pe.PEFile;
import net.jsign.powershell.PowerShellScript;

/**
 * A file that can be signed with Authenticode.
 *
 * @author Emmanuel Bourg
 */
public interface Signable {

    /**
     * Computes the digest of the file.
     * 
     * @param digest the message digest to update
     * @return the digest of the file
     * @throws IOException if an I/O error occurs
     */
    byte[] computeDigest(MessageDigest digest) throws IOException;

    /**
     * Creates the SpcIndirectDataContent structure containing the digest of the file.
     * 
     * @param digestAlgorithm the digest algorithm to use
     * @return the SpcIndirectDataContent structure in ASN.1 format
     * @throws IOException if an I/O error occurs
     */
    ASN1Object createIndirectData(DigestAlgorithm digestAlgorithm) throws IOException;

    /**
     * Returns the Authenticode signatures on the file.
     * 
     * @return the signatures
     * @throws IOException if an I/O error occurs
     */
    List<CMSSignedData> getSignatures() throws IOException;

    /**
     * Sets the signature of the file, overwriting the previous one.
     * 
     * @param signature the signature to put
     * @throws IOException if an I/O error occurs
     */
    void setSignature(CMSSignedData signature) throws IOException;

    /**
     * Saves the file.
     * 
     * @throws IOException if an I/O error occurs
     */
    void save() throws IOException;

    /**
     * Returns a signable object for the file specified.
     *
     * @param file the file that is intended to to be signed
     * @return the signable object for the specified file
     * @throws IOException if an I/O error occurs
     * @throws UnsupportedOperationException if the file specified isn't supported
     */
    static Signable of(File file) throws IOException {
        return of(file, null);
    }

    /**
     * Returns a signable object for the file specified.
     *
     * @param file     the file that is intended to to be signed
     * @param encoding the character encoding (for text files only)
     * @return the signable object for the specified file
     * @throws IOException if an I/O error occurs
     * @throws UnsupportedOperationException if the file specified isn't supported
     */
    static Signable of(File file, Charset encoding) throws IOException {
        if (PEFile.isPEFile(file)) {
            return new PEFile(file);

        } else if (MSIFile.isMSIFile(file)) {
            return new MSIFile(file);

        } else if (file.getName().endsWith(".ps1")
                || file.getName().endsWith(".psd1")
                || file.getName().endsWith(".psm1")) {
            return new PowerShellScript(file, encoding);
        } else {
            throw new UnsupportedOperationException("Unsupported file: " + file);
        }
    }
}
