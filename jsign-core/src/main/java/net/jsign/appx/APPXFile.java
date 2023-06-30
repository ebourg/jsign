/**
 * Copyright 2023 Emmanuel Bourg
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

package net.jsign.appx;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.nio.channels.SeekableByteChannel;
import java.security.DigestOutputStream;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.output.NullOutputStream;
import org.apache.poi.util.IOUtils;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;

import net.jsign.ChannelUtils;
import net.jsign.DigestAlgorithm;
import net.jsign.Signable;
import net.jsign.asn1.authenticode.AuthenticodeObjectIdentifiers;
import net.jsign.asn1.authenticode.SpcAttributeTypeAndOptionalValue;
import net.jsign.asn1.authenticode.SpcIndirectDataContent;
import net.jsign.asn1.authenticode.SpcSipInfo;
import net.jsign.asn1.authenticode.SpcUuid;

import static java.nio.charset.StandardCharsets.*;

/**
 * APPX/MSIX package.
 *
 * @author Emmanuel Bourg
 * @since 5.1
 */
public class APPXFile extends ZipFile implements Signable {

    /**
     * Create an APPXFile from the specified file.
     *
     * @param file the file to open
     * @throws IOException if an I/O error occurs
     */
    public APPXFile(File file) throws IOException {
        super(file);
        verifyPackage();
    }

    /**
     * Create an APPXFile from the specified channel.
     *
     * @param channel the channel to read the file from
     * @throws IOException if an I/O error occurs
     */
    public APPXFile(SeekableByteChannel channel) throws IOException {
        super(channel);
        verifyPackage();
    }

    private void verifyPackage() throws IOException {
        if (centralDirectory.entries.get("[Content_Types].xml") == null) {
            throw new IOException("Invalid APPX/MSIX package, [Content_Types].xml is missing");
        }
    }

    @Override
    public byte[] computeDigest(DigestAlgorithm digestAlgorithm) throws IOException {
        addContentType("/AppxSignature.p7x", "application/vnd.ms-appx.signature");

        // digest the file records
        long endOfContentOffset = centralDirectory.centralDirectoryOffset;
        if (centralDirectory.entries.containsKey("AppxSignature.p7x")) {
            endOfContentOffset = centralDirectory.entries.get("AppxSignature.p7x").getLocalHeaderOffset();
        }
        MessageDigest axpc = digestAlgorithm.getMessageDigest();
        ChannelUtils.updateDigest(channel, axpc, 0, endOfContentOffset);

        // digest the central directory
        MessageDigest axcd = digestAlgorithm.getMessageDigest();
        axcd.update(getUnsignedCentralDirectory());

        // digest the [ContentTypes].xml file
        MessageDigest axct = digestAlgorithm.getMessageDigest();
        IOUtils.copy(getInputStream("[Content_Types].xml"), new DigestOutputStream(NullOutputStream.NULL_OUTPUT_STREAM, axct));

        // digest the AppxBlockMap.xml file
        MessageDigest axbm = digestAlgorithm.getMessageDigest();
        IOUtils.copy(getInputStream("AppxBlockMap.xml"), new DigestOutputStream(NullOutputStream.NULL_OUTPUT_STREAM, axbm));

        // digest the AppxMetadata/CodeIntegrity.cat file if present
        MessageDigest axci = null;
        if (centralDirectory.entries.containsKey("AppxMetadata/CodeIntegrity.cat")) {
            axci = digestAlgorithm.getMessageDigest();
            IOUtils.copy(getInputStream("AppxMetadata/CodeIntegrity.cat"), new DigestOutputStream(NullOutputStream.NULL_OUTPUT_STREAM, axci));
        }

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write("APPX".getBytes());
        out.write("AXPC".getBytes());
        out.write(axpc.digest());
        out.write("AXCD".getBytes());
        out.write(axcd.digest());
        out.write("AXCT".getBytes());
        out.write(axct.digest());
        out.write("AXBM".getBytes());
        out.write(axbm.digest());
        if (axci != null) {
            out.write("AXCI".getBytes());
            out.write(axci.digest());
        }

        return out.toByteArray();
    }

    /**
     * Returns a copy of the central directory as if the package was unsigned.
     */
    private byte[] getUnsignedCentralDirectory() throws IOException {
        CentralDirectory centralDirectory = new CentralDirectory();
        centralDirectory.read(channel);
        if (centralDirectory.entries.containsKey("AppxSignature.p7x")) {
            CentralDirectoryFileHeader signatureHeader = centralDirectory.entries.get("AppxSignature.p7x");
            centralDirectory.entries.remove("AppxSignature.p7x");
            centralDirectory.centralDirectoryOffset = signatureHeader.getLocalHeaderOffset();
        }

        File tmp = File.createTempFile("jsign-zip-central-directory", ".bin");
        tmp.deleteOnExit();
        try (RandomAccessFile raf = new RandomAccessFile(tmp, "rw")) {
            centralDirectory.write(raf.getChannel(), centralDirectory.centralDirectoryOffset);
            return FileUtils.readFileToByteArray(tmp);
        } finally {
            tmp.delete();
        }
    }

    @Override
    public ASN1Object createIndirectData(DigestAlgorithm digestAlgorithm) throws IOException {
        AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(digestAlgorithm.oid, DERNull.INSTANCE);
        DigestInfo digestInfo = new DigestInfo(algorithmIdentifier, computeDigest(digestAlgorithm));

        boolean bundle = centralDirectory.entries.containsKey("AppxBundleManifest.xml");
        SpcUuid uuid = new SpcUuid(bundle ? "B3585F0F-DEAA-9A4B-A434-95742D92ECEB" : "4BDFC50A-07CE-E24D-B76E-23C839A09FD1");
        SpcAttributeTypeAndOptionalValue data = new SpcAttributeTypeAndOptionalValue(AuthenticodeObjectIdentifiers.SPC_SIPINFO_OBJID, new SpcSipInfo(0x01010000, uuid));

        return new SpcIndirectDataContent(data, digestInfo);
    }

    @Override
    public List<CMSSignedData> getSignatures() throws IOException {
        List<CMSSignedData> signatures = new ArrayList<>();

        if (centralDirectory.entries.containsKey("AppxSignature.p7x")) {
            InputStream in = getInputStream("AppxSignature.p7x", 1024 * 1024 /* 1MB */);
            // skip the "PKCX" header
            in.skip(4);
            byte[] signatureBytes = IOUtils.toByteArray(in);

            try {
                CMSSignedData signedData = new CMSSignedData((CMSProcessable) null, ContentInfo.getInstance(new ASN1InputStream(signatureBytes).readObject()));
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
            } catch (UnsupportedOperationException e) {
                // unsupported type, just skip
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        return signatures;
    }

    @Override
    public void setSignature(CMSSignedData signature) throws IOException {
        if (centralDirectory.entries.containsKey("AppxSignature.p7x")) {
            removeEntry("AppxSignature.p7x");
        }

        if (signature != null) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            out.write("PKCX".getBytes());
            signature.toASN1Structure().encodeTo(out, "DER");

            addEntry("AppxSignature.p7x", out.toByteArray(), false);
        }
    }

    /**
     * Add a content type to the [ContentTypes].xml file.
     */
    void addContentType(String partName, String contentType) throws IOException {
        InputStream in = getInputStream("[Content_Types].xml", 10 * 1024 * 1024 /* 10MB */);
        String contentTypes = new String(IOUtils.toByteArray(in), UTF_8);
        String override = "<Override PartName=\"" + partName + "\" ContentType=\"" + contentType + "\"/>";
        if (!contentTypes.contains(override)) {
            contentTypes = contentTypes.replace("</Types>", "<Override PartName=\"" + partName + "\" ContentType=\"" + contentType + "\"/></Types>");

            renameEntry("[Content_Types].xml", "[Content_Types].old");
            addEntry("[Content_Types].xml", contentTypes.getBytes(), true);
        }
    }

    /**
     * Get the digest algorithm used to hash the blocks in the AppxBlockMap.xml file.
     */
    @Override
    public DigestAlgorithm getRequiredDigestAlgorithm() throws IOException {
        String appxBlockMap = new String(IOUtils.toByteArray(getInputStream("AppxBlockMap.xml", 10 * 1024 * 1024 /* 10MB */)), UTF_8);

        Matcher matcher = Pattern.compile("HashMethod=\"([^\"]+)\"", Pattern.CASE_INSENSITIVE).matcher(appxBlockMap);
        if (matcher.find()) {
            switch (matcher.group(1)) {
                case "http://www.w3.org/2001/04/xmlenc#sha256":
                    return DigestAlgorithm.SHA256;
                case "http://www.w3.org/2001/04/xmldsig-more#sha384":
                    return DigestAlgorithm.SHA384;
                case "http://www.w3.org/2001/04/xmlenc#sha512":
                    return DigestAlgorithm.SHA512;
            }
        }

        return null;
    }

    @Override
    public void save() throws IOException {
    }
}
