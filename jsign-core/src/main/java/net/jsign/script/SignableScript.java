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

package net.jsign.script;

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
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;

import net.jsign.DigestAlgorithm;
import net.jsign.Signable;
import net.jsign.asn1.authenticode.AuthenticodeObjectIdentifiers;
import net.jsign.asn1.authenticode.SpcAttributeTypeAndOptionalValue;
import net.jsign.asn1.authenticode.SpcIndirectDataContent;

import static java.lang.Math.min;
import static java.nio.charset.StandardCharsets.*;

/**
 * A script (text file) that can be signed.
 *
 * @author Björn Kautler
 * @author Emmanuel Bourg
 * @since 3.0
 */
abstract class SignableScript implements Signable {

    private File file;
    private String content;
    private Charset encoding;

    /**
     * Create a script.
     * The encoding is assumed to be UTF-8.
     */
    public SignableScript() {
        this.encoding = StandardCharsets.UTF_8;
    }

    /**
     * Create a script from the specified file and load its content.
     * The encoding is assumed to be UTF-8.
     * 
     * @param file the script
     * @throws IOException if an I/O error occurs
     */
    public SignableScript(File file) throws IOException {
        this(file, StandardCharsets.UTF_8);
    }

    /**
     * Create a script from the specified file and load its content.
     * 
     * @param file     the script
     * @param encoding the encoding of the script (if null the default UTF-8 encoding is used)
     * @throws IOException if an I/O error occurs
     */
    public SignableScript(File file, Charset encoding) throws IOException {
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

    abstract String getSignatureStart();

    abstract String getSignatureEnd();

    abstract String getLineCommentStart();

    abstract String getLineCommentEnd();

    abstract ASN1Object getSpcSipInfo();

    private Pattern getSignatureBlockPattern() {
        return Pattern.compile("(?s)" +
                "\\r\\n" +
                getSignatureStart() + "\\r\\n" +
                "(?<signatureBlock>.*)" +
                getSignatureEnd() + "\\r\\n");
    }

    private Pattern getSignatureBlockRemovalPattern() {
        /** Pattern for removing signatures, even if the file EOL was converted to LF */
        return Pattern.compile("(?s)" +
                "\\r?\\n" +
                getSignatureStart() + "\\r?\\n" +
                ".*" +
                getSignatureEnd() + "\\r?\\n");
    }

    @Override
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
        Matcher matcher = getSignatureBlockPattern().matcher(getContent());
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
        
        signatureBlock = signatureBlock.replace(getLineCommentStart(), "");
        signatureBlock = signatureBlock.replace(getLineCommentEnd(), "");
        signatureBlock = signatureBlock.replaceAll("\r|\n", "");

        byte[] signatureBytes = Base64.getDecoder().decode(signatureBlock);

        try {
            return new CMSSignedData((CMSProcessable) null, ContentInfo.getInstance(new ASN1InputStream(signatureBytes).readObject()));
        } catch (IOException e) {
            throw new IllegalArgumentException("Failed to construct ContentInfo from byte[]: ", e);
        }
    }

    @Override
    public void setSignature(CMSSignedData signature) throws IOException {
        // base64 encode the signature blob
        byte[] signatureBytes = signature.toASN1Structure().getEncoded("DER");
        String signatureBlob = Base64.getEncoder().encodeToString(signatureBytes);

        // build the signed script content
        String content = getContentWithoutSignatureBlock();
        
        StringBuilder signedContent = new StringBuilder(content.length() + signatureBlob.length() + 100);
        signedContent.append(content);
        signedContent.append("\r\n");
        signedContent.append(getSignatureStart() + "\r\n");
        for (int start = 0, blobLength = signatureBlob.length(); start < blobLength; start += 64) {
            signedContent.append(getLineCommentStart());
            signedContent.append(signatureBlob, start, min(blobLength, start + 64));
            signedContent.append(getLineCommentEnd());
            signedContent.append("\r\n");
        }
        signedContent.append(getSignatureEnd() + "\r\n");
        
        this.content = signedContent.toString();
    }

    /**
     * Returns the content stripped from the signature block.
     * 
     * @return the content without the signature
     */
    private String getContentWithoutSignatureBlock() {
        return getSignatureBlockRemovalPattern().matcher(getContent()).replaceFirst("");
    }

    @Override
    public byte[] computeDigest(MessageDigest digest) {
        digest.update(getContentWithoutSignatureBlock().getBytes(UTF_16LE));
        return digest.digest();
    }

    @Override
    public ASN1Object createIndirectData(DigestAlgorithm digestAlgorithm) throws IOException {
        AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(digestAlgorithm.oid, DERNull.INSTANCE);
        DigestInfo digestInfo = new DigestInfo(algorithmIdentifier, computeDigest(digestAlgorithm.getMessageDigest()));
        
        SpcAttributeTypeAndOptionalValue data = new SpcAttributeTypeAndOptionalValue(AuthenticodeObjectIdentifiers.SPC_SIPINFO_OBJID, getSpcSipInfo());
        
        return new SpcIndirectDataContent(data, digestInfo);
    }

    @Override
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
