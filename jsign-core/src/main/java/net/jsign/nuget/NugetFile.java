/**
 * Copyright 2024 Sebastian Stamm
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

package net.jsign.nuget;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.channels.SeekableByteChannel;
import java.security.MessageDigest;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

import org.apache.poi.util.IOUtils;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.esf.CommitmentTypeIndication;
import org.bouncycastle.asn1.ess.ESSCertIDv2;
import org.bouncycastle.asn1.ess.SigningCertificateV2;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSTypedData;

import net.jsign.ChannelUtils;
import net.jsign.DigestAlgorithm;
import net.jsign.Signable;
import net.jsign.SignatureUtils;
import net.jsign.zip.CentralDirectory;
import net.jsign.zip.ZipFile;

/**
 * A NuGet package.
 * 
 * @see <a href="https://github.com/NuGet/Home/wiki/Package-Signatures-Technical-Details">NuGet Package Signatures Technical Specification</a>
 * @see <a href="https://github.com/NuGet/Home/wiki/Repository-Signatures-and-Countersignatures-Technical-Specification">NuGet Repository Signatures and Countersignatures Technical Specification</a>
 *
 * @author Sebastian Stamm
 * @since 7.0
 */
public class NugetFile extends ZipFile implements Signable {

    /** The name of the package signature entry in the archive */
    private static final String SIGNATURE_ENTRY = ".signature.p7s";

    /**
     * Create an NuGet from the specified file.
     *
     * @param file the file to open
     * @throws IOException if an I/O error occurs
     */
    public NugetFile(File file) throws IOException {
        super(file);
        verifyPackage();
    }

    /**
     * Create an NuGet from the specified channel.
     *
     * @param channel the channel to read the file from
     * @throws IOException if an I/O error occurs
     */
    public NugetFile(SeekableByteChannel channel) throws IOException {
        super(channel);
        verifyPackage();
    }

    private void verifyPackage() throws IOException {
        if (centralDirectory.entries.get("[Content_Types].xml") == null) {
            throw new IOException("Invalid NuGet package, [Content_Types].xml is missing");
        }
    }

    @Override
    public byte[] computeDigest(DigestAlgorithm digestAlgorithm) throws IOException {
        MessageDigest digest = digestAlgorithm.getMessageDigest();

        // digest the file records
        long endOfContentOffset = centralDirectory.centralDirectoryOffset;
        if (centralDirectory.entries.containsKey(SIGNATURE_ENTRY)) {
            endOfContentOffset = centralDirectory.entries.get(SIGNATURE_ENTRY).getLocalHeaderOffset();
        }
        ChannelUtils.updateDigest(channel, digest, 0, endOfContentOffset);

        // digest the central directory
        digest.update(getUnsignedCentralDirectory());
        return String.format("Version:1\n\n%s-Hash:%s\n\n", digestAlgorithm.oid, Base64.getEncoder().encodeToString(digest.digest())).getBytes();
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
    public CMSTypedData createSignedContent(DigestAlgorithm digestAlgorithm) throws IOException {
        return new CMSProcessableByteArray(PKCSObjectIdentifiers.data, computeDigest(digestAlgorithm));
    }

    @Override
    public ASN1Object createIndirectData(DigestAlgorithm digestAlgorithm) {
        throw new UnsupportedOperationException(); // not applicable here
    }

    @Override
    public List<Attribute> createSignedAttributes(X509Certificate certificate) throws CertificateEncodingException {
        List<Attribute> attributes = new ArrayList<>();

        CommitmentTypeIndication commitmentTypeIndication = new CommitmentTypeIndication(PKCSObjectIdentifiers.id_cti_ets_proofOfOrigin);
        attributes.add(new Attribute(PKCSObjectIdentifiers.id_aa_ets_commitmentType, new DERSet(commitmentTypeIndication)));
        // todo use the id-cti-ets-proofOfReceipt type for repository signatures

        // todo add the nuget-v3-service-index-url and nuget-package-owners attributes for repository signatures

        byte[] certHash = DigestAlgorithm.SHA256.getMessageDigest().digest(certificate.getEncoded());
        IssuerSerial issuerSerial = new IssuerSerial(X500Name.getInstance(certificate.getIssuerX500Principal().getEncoded()), certificate.getSerialNumber());
        SigningCertificateV2 signingCertificateV2 = new SigningCertificateV2(new ESSCertIDv2(certHash, issuerSerial));
        attributes.add(new Attribute(PKCSObjectIdentifiers.id_aa_signingCertificateV2, new DERSet(signingCertificateV2)));

        return attributes;
    }

    @Override
    public List<CMSSignedData> getSignatures() throws IOException {
        if (centralDirectory.entries.containsKey(SIGNATURE_ENTRY)) {
            InputStream in = getInputStream(SIGNATURE_ENTRY, 1024 * 1024 /* 1MB */);
            return SignatureUtils.getSignatures(IOUtils.toByteArray(in));
        } else {
            return Collections.emptyList();
        }
    }

    @Override
    public void setSignature(CMSSignedData signature) throws IOException {
        if (centralDirectory.entries.containsKey(SIGNATURE_ENTRY)) {
            removeEntry(SIGNATURE_ENTRY);
        }

        if (signature != null) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            signature.toASN1Structure().encodeTo(out, "DER");
            addEntry(SIGNATURE_ENTRY, out.toByteArray(), false);
        }
    }

    @Override
    public void save() throws IOException {
    }
}
