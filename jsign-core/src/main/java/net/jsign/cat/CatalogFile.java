/**
 * Copyright 2022 Emmanuel Bourg and contributors
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

package net.jsign.cat;

import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.util.Collections;
import java.util.List;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.util.CollectionStore;

import net.jsign.DigestAlgorithm;
import net.jsign.Signable;
import net.jsign.SignatureUtils;

/**
 * Windows Catalog file.
 *
 * @see <a href="https://docs.microsoft.com/en-us/windows-hardware/drivers/install/catalog-files">Windows Drivers - Catalog Files and Digital Signatures</a>
 * @since 4.2
 */
public class CatalogFile implements Signable {

    private final SeekableByteChannel channel;

    private CMSSignedData signedData;

    /**
     * Tells if the specified file is a Windows catalog file.
     *
     * @param file the file to check
     * @return <code>true</code> if the file is a Windows catalog, <code>false</code> otherwise
     */
    public static boolean isCatalogFile(File file) {
        if (!file.exists() || !file.isFile()) {
            return false;
        }

        try {
            CatalogFile catFile = new CatalogFile(file);
            catFile.close();
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    /**
     * Create a Windows catalog from the specified file.
     *
     * @param file the file to open
     * @throws IOException if an I/O error occurs
     */
    public CatalogFile(File file) throws IOException {
        this(Files.newByteChannel(file.toPath(), StandardOpenOption.READ, StandardOpenOption.WRITE));
    }

    /**
     * Create a Windows catalog from the specified channel.
     *
     * @param channel the channel to read the file from
     * @throws IOException if an I/O error occurs
     */
    public CatalogFile(SeekableByteChannel channel) throws IOException {
        this.channel = channel;

        channel.position(0);

        try {
            signedData = new CMSSignedData(Channels.newInputStream(channel));
        } catch (CMSException e) {
            throw new IOException("Catalog file format error", e);
        }
    }

    @Override
    public void close() throws IOException {
        channel.close();
    }

    @Override
    public CMSTypedData createSignedContent(DigestAlgorithm digestAlgorithm) {
        return signedData.getSignedContent();
    }

    @Override
    public byte[] computeDigest(DigestAlgorithm digest) {
        throw new UnsupportedOperationException();
    }

    @Override
    public ASN1Object createIndirectData(DigestAlgorithm digestAlgorithm) {
        throw new UnsupportedOperationException();
    }

    @Override
    public List<CMSSignedData> getSignatures() throws IOException {
        if (signedData.getSignerInfos().size() > 0) {
            return SignatureUtils.getSignatures(signedData);
        } else {
            return Collections.emptyList();
        }
    }

    @Override
    public void setSignature(CMSSignedData signature) {
        if (signature != null) {
            signedData = signature;
        } else {
            // remove the signatures and the certificates
            try {
                signedData = CMSSignedData.replaceSigners(signedData, new SignerInformationStore(Collections.emptyList()));
                CollectionStore<?> emptyStore = new CollectionStore<>(Collections.emptyList());
                signedData = CMSSignedData.replaceCertificatesAndCRLs(signedData, emptyStore, emptyStore, emptyStore);
            } catch (CMSException e) {
                throw new RuntimeException(e);
            }
        }
    }

    @Override
    public void save() throws IOException {
        channel.position(0);
        channel.truncate(0);
        channel.write(ByteBuffer.wrap(signedData.getEncoded("DER")));
    }
}
