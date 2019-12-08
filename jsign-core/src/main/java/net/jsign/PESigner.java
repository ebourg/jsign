/**
 * Copyright 2012 Emmanuel Bourg
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

import java.io.File;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.util.List;

import net.jsign.asn1.authenticode.AuthenticodeObjectIdentifiers;
import net.jsign.asn1.authenticode.SpcAttributeTypeAndOptionalValue;
import net.jsign.asn1.authenticode.SpcIndirectDataContent;
import net.jsign.asn1.authenticode.SpcPeImageData;
import net.jsign.pe.CertificateTableEntry;
import net.jsign.pe.DataDirectory;
import net.jsign.pe.DataDirectoryType;
import net.jsign.pe.PEFile;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;

/**
 * Sign a portable executable file. Timestamping is enabled by default
 * and relies on the Comodo server (http://timestamp.comodoca.com/authenticode).
 * 
 * @see <a href="http://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/Authenticode_PE.docx">Windows Authenticode Portable Executable Signature Format</a>
 * @see <a href="http://msdn.microsoft.com/en-us/library/windows/desktop/bb931395%28v=vs.85%29.aspx?ppud=4">Time Stamping Authenticode Signatures</a>
 * 
 * @author Emmanuel Bourg
 * @since 1.0
 */
public class PESigner extends AuthenticodeSigner<PESigner, PEFile> {

    /**
     * Create a PESigner with the specified certificate chain and private key.
     *
     * @param chain       the certificate chain. The first certificate is the signing certificate
     * @param privateKey  the private key
     * @throws IllegalArgumentException if the chain is empty
     */
    public PESigner(Certificate[] chain, PrivateKey privateKey) {
        super(chain, privateKey);
    }

    /**
     * Create a PESigner with a certificate chain and private key from the specified keystore.
     *
     * @param keystore the keystore holding the certificate and the private key
     * @param alias    the alias of the certificate in the keystore
     * @param password the password to get the private key
     */
    public PESigner(KeyStore keystore, String alias, String password) throws NoSuchAlgorithmException, KeyStoreException, UnrecoverableKeyException {
        super(keystore, alias, password);
    }

    /**
     * Set the URL of the timestamping authority. Both RFC 3161 (as used for jar signing)
     * and Authenticode timestamping services are supported.
     * 
     * @deprecated Use {@link #withTimestampingAuthority(String)} instead
     */
    public PESigner withTimestampingAutority(String url) {
        return withTimestampingAuthority(url);
    }

    /**
     * Set the URLs of the timestamping authorities. Both RFC 3161 (as used for jar signing)
     * and Authenticode timestamping services are supported.
     *
     * @since 2.0
     * @deprecated Use {@link #withTimestampingAuthority(String...)} instead
     */
    public PESigner withTimestampingAutority(String... url) {
        return withTimestampingAuthority(url);
    }

    @Override
    void sign(File file) throws Exception {
        PEFile peFile;
        try {
            peFile = new PEFile(file);
        } catch (IOException e) {
            throw new SignerException("Couldn't open the executable file " + file, e);
        }
        try {
            sign(peFile);
        } finally {
            peFile.close();
        }
    }

    /**
     * Sign the specified executable file.
     *
     * @throws Exception
     */
    @Override
    public void sign(PEFile file) throws Exception {
        // pad the file on a 8 byte boundary
        // todo only if there was no previous certificate table
        file.pad(8);
        
        if (replace) {
            DataDirectory certificateTable = file.getDataDirectory(DataDirectoryType.CERTIFICATE_TABLE);
            if (certificateTable != null && !certificateTable.isTrailing()) {
                // erase the previous signature
                certificateTable.erase();
                certificateTable.write(0, 0);
            }
        }
        
        CMSSignedData sigData = createSignedData(file);
        
        List<CMSSignedData> signatures = file.getSignatures();
        if (!signatures.isEmpty() && !replace) {
            // append the nested signature
            sigData = addNestedSignature(signatures.get(0), sigData);
        }

        CertificateTableEntry entry = new CertificateTableEntry(sigData);
        
        file.writeDataDirectory(DataDirectoryType.CERTIFICATE_TABLE, entry.toBytes());
        file.close();
    }

    @Override
    protected ASN1Object createIndirectData(PEFile file) throws IOException {
        AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(digestAlgorithm.oid, DERNull.INSTANCE);
        DigestInfo digestInfo = new DigestInfo(algorithmIdentifier, file.computeDigest(digestAlgorithm));
        SpcAttributeTypeAndOptionalValue data = new SpcAttributeTypeAndOptionalValue(AuthenticodeObjectIdentifiers.SPC_PE_IMAGE_DATA_OBJID, new SpcPeImageData());

        return new SpcIndirectDataContent(data, digestInfo);
    }
}
