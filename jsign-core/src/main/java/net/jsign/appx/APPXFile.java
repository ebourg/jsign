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
import java.nio.channels.SeekableByteChannel;
import java.security.DigestOutputStream;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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
import net.jsign.zip.CentralDirectory;
import net.jsign.zip.ZipFile;

import static java.nio.charset.StandardCharsets.*;

/**
 * APPX/MSIX package.
 *
 * @author Emmanuel Bourg
 * @since 6.0
 */
public class APPXFile extends ZipFile implements Signable {

    /** The name of the package signature entry in the archive */
    private static final String SIGNATURE_ENTRY = "AppxSignature.p7x";

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
        addContentType("/" + SIGNATURE_ENTRY, "application/vnd.ms-appx.signature");

        // digest the file records
        long endOfContentOffset = centralDirectory.centralDirectoryOffset;
        if (centralDirectory.entries.containsKey(SIGNATURE_ENTRY)) {
            endOfContentOffset = centralDirectory.entries.get(SIGNATURE_ENTRY).getLocalHeaderOffset();
        }
        MessageDigest axpc = digestAlgorithm.getMessageDigest();
        ChannelUtils.updateDigest(channel, axpc, 0, endOfContentOffset);

        // digest the central directory
        MessageDigest axcd = digestAlgorithm.getMessageDigest();
        axcd.update(getUnsignedCentralDirectory());

        // digest the [ContentTypes].xml file
        MessageDigest axct = digestAlgorithm.getMessageDigest();
        IOUtils.copy(getInputStream("[Content_Types].xml"), new DigestOutputStream(NullOutputStream.INSTANCE, axct));

        // digest the AppxBlockMap.xml file
        MessageDigest axbm = digestAlgorithm.getMessageDigest();
        IOUtils.copy(getInputStream("AppxBlockMap.xml"), new DigestOutputStream(NullOutputStream.INSTANCE, axbm));

        // digest the AppxMetadata/CodeIntegrity.cat file if present
        MessageDigest axci = null;
        if (centralDirectory.entries.containsKey("AppxMetadata/CodeIntegrity.cat")) {
            axci = digestAlgorithm.getMessageDigest();
            IOUtils.copy(getInputStream("AppxMetadata/CodeIntegrity.cat"), new DigestOutputStream(NullOutputStream.INSTANCE, axci));
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
        centralDirectory.removeEntry(SIGNATURE_ENTRY);
        return centralDirectory.toBytes();
    }

    @Override
    public ASN1Object createIndirectData(DigestAlgorithm digestAlgorithm) throws IOException {
        AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(digestAlgorithm.oid, DERNull.INSTANCE);
        DigestInfo digestInfo = new DigestInfo(algorithmIdentifier, computeDigest(digestAlgorithm));

        SpcUuid uuid = new SpcUuid(isBundle() ? "B3585F0F-DEAA-9A4B-A434-95742D92ECEB" : "4BDFC50A-07CE-E24D-B76E-23C839A09FD1");
        SpcAttributeTypeAndOptionalValue data = new SpcAttributeTypeAndOptionalValue(AuthenticodeObjectIdentifiers.SPC_SIPINFO_OBJID, new SpcSipInfo(0x01010000, uuid));

        return new SpcIndirectDataContent(data, digestInfo);
    }

    private static String normalized(String name) {
        return name.replaceAll(", ", ",").replace(",ST=", ",S=");
    }

    @Override
    public void validate(Certificate certificate) throws IOException, IllegalArgumentException {
        String name = ((X509Certificate) certificate).getSubjectX500Principal().getName();
        String publisher = getPublisher();
        if (!normalized(name).equals(normalized(publisher))) {
            throw new IllegalArgumentException("The app manifest publisher name (" + publisher + ") must match the subject name of the signing certificate (" + name + ")");
        }
    }

    /**
     * Tells if the package is a bundle.
     */
    boolean isBundle() {
        return centralDirectory.entries.containsKey("AppxMetadata/AppxBundleManifest.xml");
    }

    /**
     * Returns the publisher of the package.
     */
    String getPublisher() throws IOException {
        InputStream in = getInputStream(isBundle() ? "AppxMetadata/AppxBundleManifest.xml" : "AppxManifest.xml", 10 * 1024 * 1024 /* 10MB */);
        String manifest = new String(IOUtils.toByteArray(in), UTF_8);

        Pattern pattern = Pattern.compile("Publisher\\s*=\\s*\"([^\"]+)", Pattern.CASE_INSENSITIVE);
        Matcher matcher = pattern.matcher(manifest);
        return matcher.find() ? matcher.group(1) : null;
    }

    @Override
    public List<CMSSignedData> getSignatures() throws IOException {
        List<CMSSignedData> signatures = new ArrayList<>();

        if (centralDirectory.entries.containsKey(SIGNATURE_ENTRY)) {
            InputStream in = getInputStream(SIGNATURE_ENTRY, 1024 * 1024 /* 1MB */);
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
            } catch (Exception | StackOverflowError e) {
                e.printStackTrace();
            }
        }

        return signatures;
    }

    @Override
    public void setSignature(CMSSignedData signature) throws IOException {
        if (centralDirectory.entries.containsKey(SIGNATURE_ENTRY)) {
            removeEntry(SIGNATURE_ENTRY);
        }

        if (signature != null) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            out.write("PKCX".getBytes());
            signature.toASN1Structure().encodeTo(out, "DER");

            addEntry(SIGNATURE_ENTRY, out.toByteArray(), false);
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

    @Override
    public void save() throws IOException {
    }
}
