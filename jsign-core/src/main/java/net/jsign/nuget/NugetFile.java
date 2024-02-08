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
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import org.apache.poi.util.IOUtils;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSTypedData;

import net.jsign.ChannelUtils;
import net.jsign.DigestAlgorithm;
import net.jsign.Signable;
import net.jsign.zip.CentralDirectory;
import net.jsign.zip.ZipFile;

/**
 * A NuGet package.
 * 
 * @see <a href="https://github.com/NuGet/Home/wiki/Package-Signatures-Technical-Details">NuGet Package Signatures Technical Specification</a>
 *
 * @author Sebastian Stamm
 * @since 6.1
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
    public List<CMSSignedData> getSignatures() throws IOException {
        List<CMSSignedData> signatures = new ArrayList<>();

        if (centralDirectory.entries.containsKey(SIGNATURE_ENTRY)) {
            InputStream in = getInputStream(SIGNATURE_ENTRY, 1024 * 1024 /* 1MB */);
            byte[] signatureBytes = IOUtils.toByteArray(in);

            try {
                signatures.add(new CMSSignedData(new ASN1InputStream(signatureBytes)));
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
            signature.toASN1Structure().encodeTo(out, "DER");
            addEntry(SIGNATURE_ENTRY, out.toByteArray(), false);
        }
    }

    @Override
    public void save() throws IOException {
    }
}
