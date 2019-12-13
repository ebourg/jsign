/**
 * Copyright 2019 Björn Kautler
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

package net.jsign.powershell;

import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;

import net.jsign.asn1.authenticode.AuthenticodeObjectIdentifiers;

import static java.lang.Math.*;
import static java.nio.charset.StandardCharsets.*;

/**
 * A PowerShell script.
 * 
 * @since 3.0
 */
public class PowerShellScript {

    private static final Pattern SIGNATURE_BLOCK_PATTERN = Pattern.compile("(?s)" +
            "\\r\\n" +
            "# SIG # Begin signature block\\r\\n" +
            "(?<signatureBlock>.*)" +
            "# SIG # End signature block\\r\\n");

    /** Pattern for removing signatures, even if the file EOL was converted to LF */
    private static final Pattern SIGNATURE_BLOCK_REMOVAL_PATTERN = Pattern.compile("(?s)" +
            "\\r?\\n" +
            "# SIG # Begin signature block.*$");

    private File file;
    private String content;
    private Charset encoding;

    /**
     * Create a PowerShell script.
     * The encoding is assumed to be UTF-8.
     */
    public PowerShellScript() {
        this.encoding = StandardCharsets.UTF_8;
    }

    /**
     * Create a PowerShell script from the specified file and load its content.
     * The encoding is assumed to be UTF-8.
     * 
     * @param file the PowerShell script
     * @throws IOException if an I/O error occurs
     */
    public PowerShellScript(File file) throws IOException {
        this(file, StandardCharsets.UTF_8);
    }

    /**
     * Create a PowerShell script from the specified file and load its content.
     * 
     * @param file     the PowerShell script
     * @param encoding the encoding of the script (if null the default UTF-8 encoding is used)
     * @throws IOException if an I/O error occurs
     */
    public PowerShellScript(File file, Charset encoding) throws IOException {
        this.file = file;
        this.encoding = encoding != null ? encoding : StandardCharsets.UTF_8;
        setContent(new String(Files.readAllBytes(file.toPath()), this.encoding));
    }

    /**
     * Returns the content of the script.
     * 
     * @return the content of the script
     */
    public String getContent() {
        return content;
    }

    /**
     * Sets the content of the script.
     * 
     * @param content the content of the script
     */
    public void setContent(String content) {
        this.content = content;
    }

    /**
     * Returns the authenticode signatures on the file.
     * 
     * @return the signatures
     */
    public List<CMSSignedData> getSignatures() {
        List<CMSSignedData> signatures = new ArrayList<>();
        
        try {
            CMSSignedData signedData = decodeSignatureBlock();
            if (signedData != null) {
                signatures.add(signedData);

                // look for nested signatures
                SignerInformation signerInformation = signedData.getSignerInfos().getSigners().iterator().next();
                AttributeTable unsignedAttributes = signerInformation.getUnsignedAttributes();
                if (unsignedAttributes != null) {
                    Attribute nestedSignatures = unsignedAttributes.get(AuthenticodeObjectIdentifiers.SPC_NESTED_SIGNATURE_OBJID);
                    if (nestedSignatures != null) {
                        for (ASN1Encodable nestedSignature : nestedSignatures.getAttrValues()) {
                            signatures.add(new CMSSignedData((CMSProcessable) null, ContentInfo.getInstance(nestedSignature)));
                        }
                    }
                }
            }
        } catch (UnsupportedOperationException e) {
            // unsupported type, just skip
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        return signatures;
    }

    /**
     * Returns the signature block.
     * 
     * @return the signature block
     */
    private String getSignatureBlock() {
        Matcher matcher = SIGNATURE_BLOCK_PATTERN.matcher(getContent());
        if (!matcher.find()) {
            return null;
        }
        
        return matcher.group("signatureBlock");
    }

    private CMSSignedData decodeSignatureBlock() throws CMSException {
        String signatureBlock = getSignatureBlock();
        if (signatureBlock == null) {
            return null;
        }
        
        signatureBlock = signatureBlock.replaceAll("# ", "");
        signatureBlock = signatureBlock.replaceAll("\r|\n", "");

        byte[] signatureBytes = Base64.getDecoder().decode(signatureBlock);

        try {
            return new CMSSignedData((CMSProcessable) null, ContentInfo.getInstance(new ASN1InputStream(signatureBytes).readObject()));
        } catch (IOException e) {
            throw new IllegalArgumentException("Failed to construct ContentInfo from byte[]: ", e);
        }
    }

    public void setSignature(CMSSignedData signature) throws IOException {
        // base64 encode the signature blob
        byte[] signatureBytes = signature.toASN1Structure().getEncoded("DER");
        String signatureBlob = Base64.getEncoder().encodeToString(signatureBytes);

        // build the signed script content
        String content = getContentWithoutSignatureBlock();
        
        StringBuilder signedContent = new StringBuilder(content.length() + signatureBlob.length() + 100);
        signedContent.append(content);
        signedContent.append("\r\n");
        signedContent.append("# SIG # Begin signature block\r\n");
        for (int start = 0, blobLength = signatureBlob.length(); start < blobLength; start += 64) {
            signedContent.append("# ");
            signedContent.append(signatureBlob, start, min(blobLength, start + 64));
            signedContent.append("\r\n");
        }
        signedContent.append("# SIG # End signature block\r\n");
        
        this.content = signedContent.toString();
    }

    /**
     * Returns the content stripped from the signature block.
     * 
     * @return the content without the signature
     */
    private String getContentWithoutSignatureBlock() {
        return SIGNATURE_BLOCK_REMOVAL_PATTERN.matcher(getContent()).replaceFirst("");
    }

    public byte[] computeDigest(MessageDigest digest) {
        digest.update(getContentWithoutSignatureBlock().getBytes(UTF_16LE));
        return digest.digest();
    }

    /**
     * Save the script.
     * 
     * @throws IOException if an I/O error occurs
     */
    public void save() throws IOException {
        if (file != null) {
            save(file);
        }
    }

    /**
     * Save the script to the specified file.
     * 
     * @param file the file to write
     * @throws IOException if an I/O error occurs
     */
    public void save(File file) throws IOException {
        Files.write(file.toPath(), getContent().getBytes(encoding));
    }
}
