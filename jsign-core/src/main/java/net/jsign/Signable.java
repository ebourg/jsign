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

import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.util.List;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cms.CMSSignedData;

import net.jsign.asn1.authenticode.AuthenticodeObjectIdentifiers;
import net.jsign.cat.CatalogFile;
import net.jsign.mscab.MSCabinetFile;
import net.jsign.msi.MSIFile;
import net.jsign.appx.APPXFile;
import net.jsign.pe.PEFile;
import net.jsign.script.JScript;
import net.jsign.script.PowerShellScript;
import net.jsign.script.PowerShellXMLScript;
import net.jsign.script.VBScript;
import net.jsign.script.WindowsScript;

/**
 * A file that can be signed with Authenticode.
 *
 * @author Emmanuel Bourg
 */
public interface Signable extends Closeable {

    /**
     * Returns the digests algorithm required for the signature.
     * Some formats such as APPX/MSIX require a specific digest algorithm defined in the file metadata.
     *
     * @return the digest algorithm required for the signature, or null to use the default algorithm
     * @since 5.1
     */
    default DigestAlgorithm getRequiredDigestAlgorithm() throws IOException {
        return null;
    }

    /**
     * Creates the ContentInfo structure to be signed.
     *
     * @param digestAlgorithm the digest algorithm to use
     * @return the ContentInfo structure in ASN.1 format
     * @throws IOException if an I/O error occurs
     * @since 4.2
     */
    default ContentInfo createContentInfo(DigestAlgorithm digestAlgorithm) throws IOException {
        return new ContentInfo(AuthenticodeObjectIdentifiers.SPC_INDIRECT_DATA_OBJID, createIndirectData(digestAlgorithm));
    }

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
     * @param signature the signature to put, or null to remove the signature
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
     * @param encoding the character encoding (for text files only).
     *                 If the file has a byte order mark this parameter is ignored.
     * @return the signable object for the specified file
     * @throws IOException if an I/O error occurs
     * @throws UnsupportedOperationException if the file specified isn't supported
     */
    static Signable of(File file, Charset encoding) throws IOException {
        if (PEFile.isPEFile(file)) {
            return new PEFile(file);

        } else if (MSIFile.isMSIFile(file)) {
            return new MSIFile(file);

        } else if (MSCabinetFile.isMSCabinetFile(file)) {
            return new MSCabinetFile(file);

        } else if (CatalogFile.isCatalogFile(file)) {
            return new CatalogFile(file);

        } else if (file.getName().endsWith(".ps1")
                || file.getName().endsWith(".psd1")
                || file.getName().endsWith(".psm1")) {
            return new PowerShellScript(file, encoding);

        } else if (file.getName().endsWith(".ps1xml")) {
            return new PowerShellXMLScript(file, encoding);

        } else if (file.getName().endsWith(".vbs")
                || file.getName().endsWith(".vbe")) {
            return new VBScript(file, encoding);

        } else if (file.getName().endsWith(".js")
                || file.getName().endsWith(".jse")) {
            return new JScript(file, encoding);

        } else if (file.getName().endsWith(".wsf")) {
            return new WindowsScript(file, encoding);

        } else if (file.getName().endsWith(".msix")
                || file.getName().endsWith(".msixbundle")
                || file.getName().endsWith(".appx")
                || file.getName().endsWith(".appxbundle")) {
            return new APPXFile(file);

        } else {
            throw new UnsupportedOperationException("Unsupported file: " + file);
        }
    }
}
