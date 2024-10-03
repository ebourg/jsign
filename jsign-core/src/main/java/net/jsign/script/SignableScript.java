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

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.io.ByteOrderMark;
import org.apache.commons.io.IOUtils;
import org.apache.commons.io.input.BOMInputStream;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.cms.CMSSignedData;

import net.jsign.DigestAlgorithm;
import net.jsign.Signable;
import net.jsign.SignatureUtils;
import net.jsign.asn1.authenticode.AuthenticodeObjectIdentifiers;
import net.jsign.asn1.authenticode.SpcAttributeTypeAndOptionalValue;
import net.jsign.asn1.authenticode.SpcIndirectDataContent;

import static java.lang.Math.*;
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
    private byte[] bom;

    /**
     * Create a script.
     * The encoding is assumed to be UTF-8.
     */
    public SignableScript() {
        this.encoding = StandardCharsets.UTF_8;
    }

    /**
     * Create a script from the specified file and load its content.
     * If the file has no byte order mark the encoding is assumed to be UTF-8.
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
     * @param encoding the encoding of the script if there is no byte order mark (if null UTF-8 is used by default)
     * @throws IOException if an I/O error occurs
     */
    public SignableScript(File file, Charset encoding) throws IOException {
        this.file = file;
        this.encoding = encoding != null ? encoding : StandardCharsets.UTF_8;

        ByteOrderMark[] supportedBOMs = new ByteOrderMark[] { ByteOrderMark.UTF_8, ByteOrderMark.UTF_16BE, ByteOrderMark.UTF_16LE };
        try (BOMInputStream in = new BOMInputStream(new BufferedInputStream(new FileInputStream(file)), isByteOrderMarkSigned(), supportedBOMs)) {
            if (in.hasBOM()) {
                this.encoding = Charset.forName(in.getBOMCharsetName());
                if (!isByteOrderMarkSigned()) {
                    bom = in.getBOM().getBytes();
                }
            } else if (StandardCharsets.UTF_8.equals(encoding) && !isUTF8AutoDetected()) {
                // .vbs, .js and .ps1xml files are decoded as Windows-1252 even when encoded in UTF-8
                this.encoding = Windows1252Extended.INSTANCE;
            }

            setContent(new String(IOUtils.toByteArray(in), this.encoding));
        }
    }

    /**
     * Tells if the byte order mark (BOM) should be hashed when creating the signature.
     */
    abstract boolean isByteOrderMarkSigned();

    /**
     * Tells if Windows automatically detects bom-less UTF-8 encoded files of this type.
     */
    boolean isUTF8AutoDetected() {
        return true;
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

    /** Pattern for removing signatures, even if the file EOL was converted to LF */
    private Pattern getSignatureBlockRemovalPattern() {
        return Pattern.compile("(?s)" +
                "\\r?\\n" +
                getSignatureStart() + "\\r?\\n" +
                ".*" +
                getSignatureEnd() + "\\r?\\n");
    }

    @Override
    public List<CMSSignedData> getSignatures() throws IOException {
        byte[] data = decodeSignatureBlock();
        return data != null ? SignatureUtils.getSignatures(decodeSignatureBlock()) : new ArrayList<>();
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

    private byte[] decodeSignatureBlock() {
        String signatureBlock = getSignatureBlock();
        if (signatureBlock == null) {
            return null;
        }
        
        signatureBlock = signatureBlock.replace(getLineCommentStart(), "");
        signatureBlock = signatureBlock.replace(getLineCommentEnd(), "");
        signatureBlock = signatureBlock.replaceAll("[\r\n]", "");

        return Base64.getDecoder().decode(signatureBlock);
    }

    @Override
    public void setSignature(CMSSignedData signature) throws IOException {
        // build the signed script content
        String content = getContentWithoutSignatureBlock();
        if (signature != null) {
            int pos = getSignatureInsertionPoint(content);

            this.content = content.substring(0, pos) + createSignatureBlock(signature) + content.substring(pos);
        } else {
            this.content = content;
        }
    }

    private String createSignatureBlock(CMSSignedData signature) throws IOException {
        // base64 encode the signature blob
        byte[] signatureBytes = signature.toASN1Structure().getEncoded("DER");
        String signatureBlob = Base64.getEncoder().encodeToString(signatureBytes);
        
        StringBuilder signatureBlock = new StringBuilder();
        signatureBlock.append("\r\n");
        signatureBlock.append(getSignatureStart() + "\r\n");
        for (int start = 0, blobLength = signatureBlob.length(); start < blobLength; start += 64) {
            signatureBlock.append(getLineCommentStart());
            signatureBlock.append(signatureBlob, start, min(blobLength, start + 64));
            signatureBlock.append(getLineCommentEnd());
            signatureBlock.append("\r\n");
        }
        signatureBlock.append(getSignatureEnd() + "\r\n");
        
        return signatureBlock.toString();
    }

    protected int getSignatureInsertionPoint(String content) {
        return content.length();
    }

    /**
     * Returns the content stripped from the signature block.
     * 
     * @return the content without the signature
     */
    protected String getContentWithoutSignatureBlock() {
        return getSignatureBlockRemovalPattern().matcher(getContent()).replaceFirst("");
    }

    @Override
    public byte[] computeDigest(DigestAlgorithm digestAlgorithm) {
        MessageDigest digest = digestAlgorithm.getMessageDigest();
        digest.update(getContentWithoutSignatureBlock().getBytes(UTF_16LE));
        return digest.digest();
    }

    @Override
    public ASN1Object createIndirectData(DigestAlgorithm digestAlgorithm) {
        AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(digestAlgorithm.oid, DERNull.INSTANCE);
        DigestInfo digestInfo = new DigestInfo(algorithmIdentifier, computeDigest(digestAlgorithm));
        
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
        try (FileOutputStream out = new FileOutputStream(file)) {
            if (bom != null) {
                out.write(bom);
            }
            out.write(getContent().getBytes(encoding));
            out.flush();
        }
    }

    @Override
    public void close() throws IOException {
    }
}
