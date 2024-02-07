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
import org.bouncycastle.cms.CMSSignedData;

import net.jsign.ChannelUtils;
import net.jsign.DigestAlgorithm;
import net.jsign.Signable;
import net.jsign.zip.CentralDirectoryFileHeader;
import net.jsign.zip.ZipFile;

/**
 * A Nuget package.
 * 
 * @see <a
 *      href=" https://github.com/NuGet/Home/wiki/Package-Signatures-Technical-Details">Package-Signatures-Technical-Details</a>
 *
 * @author Sebastian Stamm
 * @since 6.1
 */
public class NugetFile extends ZipFile implements Signable {

    /** The package signature file */
    static final String SIGNATURE_FILE = ".signature.p7s";

    /** properties document of the signature */
    private static final String PROPERTIES_DOC = "Version:1\n\n%s-Hash:%s\n\n";

    /**
     * Create an Nuget from the specified file.
     *
     * @param file the file to open
     * @throws IOException if an I/O error occurs
     */
    public NugetFile(File file) throws IOException {
        super(file);
        verifyPackage();
    }

    /**
     * Create an Nuget from the specified channel.
     *
     * @param channel the channel to read the file from
     * @throws IOException if an I/O error occurs
     */
    public NugetFile(SeekableByteChannel channel) throws IOException {
        super(channel);
        verifyPackage();
    }

    @Override
    public byte[] computeDigest(DigestAlgorithm digestAlgorithm) throws IOException {
        MessageDigest digest = digestAlgorithm.getMessageDigest();

        // if a SIGNATURE_FILE exists, skip it
        List<String> dir = new ArrayList<>(centralDirectory.entries.keySet());
        int sigIdx = dir.indexOf(SIGNATURE_FILE);

        if (sigIdx != -1) {
            // read until SIGNATURE_FILE
            ChannelUtils.updateDigest(channel, digest, 0, centralDirectory.entries.get(SIGNATURE_FILE).getLocalHeaderOffset());
            if (sigIdx < (dir.size() - 1)) {
                CentralDirectoryFileHeader next = centralDirectory.entries.get(dir.get(sigIdx + 1));
                ChannelUtils.updateDigest(channel, digest, next.getLocalHeaderOffset(), (centralDirectory.centralDirectoryOffset - next.getLocalHeaderOffset()));
            }
        } else {
            ChannelUtils.updateDigest(channel, digest, 0, centralDirectory.centralDirectoryOffset);
        }

        // digest the central directory
        digest.update(getUnsignedCentralDirectory(SIGNATURE_FILE));
        return String.format(PROPERTIES_DOC, digestAlgorithm.oid, Base64.getEncoder().encodeToString(digest.digest())).getBytes();
    }

    /** not used because ContentInfo is not appicable here */
    @Override
    public ASN1Object createIndirectData(DigestAlgorithm digestAlgorithm) throws IOException {
        throw new RuntimeException("not applicable");
    }

    @Override
    public List<CMSSignedData> getSignatures() throws IOException {
        List<CMSSignedData> signatures = new ArrayList<>();

        if (centralDirectory.entries.containsKey(SIGNATURE_FILE)) {
            InputStream in = getInputStream(SIGNATURE_FILE, 1024 * 1024 /* 1MB */);
            byte[] signatureBytes = IOUtils.toByteArray(in);

            try {
                CMSSignedData signedData = new CMSSignedData(new ASN1InputStream(signatureBytes));
                signatures.add(signedData);
            } catch (Exception | StackOverflowError e) {
                e.printStackTrace();
            }
        }
        return signatures;
    }

    @Override
    public void setSignature(CMSSignedData signature) throws IOException {
        if (centralDirectory.entries.containsKey(SIGNATURE_FILE)) {
            removeEntry(SIGNATURE_FILE);
        }

        if (signature != null) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            signature.toASN1Structure().encodeTo(out, "DER");
            addEntry(SIGNATURE_FILE, out.toByteArray(), false);
        }
    }

    private void verifyPackage() throws IOException {
        if (centralDirectory.entries.get("[Content_Types].xml") == null) {
            throw new IOException("Invalid Nuget package, [Content_Types].xml is missing");
        }
    }

    @Override
    public void save() throws IOException {
        // nothing to do
    }

}
