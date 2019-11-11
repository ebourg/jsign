/*
 * Copyright 2012 Emmanuel Bourg
 * Copyright 2019 Björn Kautler
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

import net.jsign.asn1.authenticode.AuthenticodeObjectIdentifiers;
import net.jsign.asn1.authenticode.SpcAttributeTypeAndOptionalValue;
import net.jsign.asn1.authenticode.SpcPeImageData;
import net.jsign.pe.CertificateTableEntry;
import net.jsign.pe.DataDirectory;
import net.jsign.pe.DataDirectoryType;
import net.jsign.pe.PEFile;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.util.List;

import static net.jsign.asn1.authenticode.AuthenticodeObjectIdentifiers.SPC_PE_IMAGE_DATA_OBJID;

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
public class PESigner extends BaseSigner<PESigner, PEFile> {

    private boolean replace;

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
     * Enable or disable the replacement of the previous signatures (disabled by default).
     *
     * @since 2.0
     */
    public PESigner withSignaturesReplaced(boolean replace) {
        this.replace = replace;
        return this;
    }

    /**
     * Sign the specified executable file.
     *
     * @throws Exception
     */
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

        // compute the signature
        CMSSignedData sigData = computeSignedData(file);

        List<CMSSignedData> signatures = file.getSignatures();
        if (!signatures.isEmpty() && !replace) {
            // append the nested signature
            sigData = addNestedSignature(signatures.get(0), sigData);
        }

        CertificateTableEntry entry = new CertificateTableEntry(sigData);

        file.writeDataDirectory(DataDirectoryType.CERTIFICATE_TABLE, entry.toBytes());
        file.close();
    }

    private CMSSignedData addNestedSignature(CMSSignedData primary, CMSSignedData secondary) throws CMSException {
        SignerInformation signerInformation = primary.getSignerInfos().getSigners().iterator().next();

        AttributeTable unsignedAttributes = signerInformation.getUnsignedAttributes();
        if (unsignedAttributes == null) {
            unsignedAttributes = new AttributeTable(new DERSet());
        }
        Attribute nestedSignaturesAttribute = unsignedAttributes.get(AuthenticodeObjectIdentifiers.SPC_NESTED_SIGNATURE_OBJID);
        if (nestedSignaturesAttribute == null) {
            // first nested signature
            unsignedAttributes = unsignedAttributes.add(AuthenticodeObjectIdentifiers.SPC_NESTED_SIGNATURE_OBJID, secondary.toASN1Structure());
        } else {
            // append the signature to the previous nested signatures
            ASN1EncodableVector nestedSignatures = new ASN1EncodableVector();
            for (ASN1Encodable nestedSignature : nestedSignaturesAttribute.getAttrValues()) {
                nestedSignatures.add(nestedSignature);
            }
            nestedSignatures.add(secondary.toASN1Structure());

            ASN1EncodableVector attributes = unsignedAttributes.remove(AuthenticodeObjectIdentifiers.SPC_NESTED_SIGNATURE_OBJID).toASN1EncodableVector();
            attributes.add(new Attribute(AuthenticodeObjectIdentifiers.SPC_NESTED_SIGNATURE_OBJID, new DERSet(nestedSignatures)));

            unsignedAttributes = new AttributeTable(attributes);
        }

        signerInformation = SignerInformation.replaceUnsignedAttributes(signerInformation, unsignedAttributes);
        return CMSSignedData.replaceSigners(primary, new SignerInformationStore(signerInformation));
    }

    @Override
    byte[] computeDigest(DigestAlgorithm digestAlgorithm, PEFile signee) throws IOException {
        return signee.computeDigest(digestAlgorithm);
    }

    @Override
    SpcAttributeTypeAndOptionalValue createSpiAttribute(DigestAlgorithm digestAlgorithm, PEFile signee) {
        return new SpcAttributeTypeAndOptionalValue(SPC_PE_IMAGE_DATA_OBJID, new SpcPeImageData());
    }
}
