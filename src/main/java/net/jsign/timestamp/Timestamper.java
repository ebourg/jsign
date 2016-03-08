/**
 * Copyright 2014 Emmanuel Bourg
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

package net.jsign.timestamp;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;

import net.jsign.DigestAlgorithm;
import net.jsign.asn1.authenticode.AuthenticodeSignedDataGenerator;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.Store;

/**
 * Interface for a timestamping service.
 * 
 * @author Emmanuel Bourg
 * @since 1.3
 */
public abstract class Timestamper {

    /** The URL of the timestamping service */
    protected URL tsaurl;

    public void setURL(String tsaurl) {
        try {
            this.tsaurl = new URL(tsaurl);
        } catch (MalformedURLException e) {
            e.printStackTrace();
        }
    }

    public CMSSignedData timestamp(DigestAlgorithm algo, CMSSignedData sigData) throws IOException, CMSException {
        SignerInformation signerInformation = ((SignerInformation) sigData.getSignerInfos().getSigners().iterator().next());

        CMSSignedData token = timestamp(algo, signerInformation.toASN1Structure().getEncryptedDigest().getOctets());

        SignerInformation timestampSignerInformation = (SignerInformation) token.getSignerInfos().getSigners().iterator().next();
        
        Attribute counterSignature = new Attribute(CMSAttributes.counterSignature, new DERSet(timestampSignerInformation.toASN1Structure()));
        
        signerInformation = SignerInformation.replaceUnsignedAttributes(signerInformation, new AttributeTable(new DERSet(counterSignature)));
        
        // add the certificates for the timestamp authority
        Collection<?> certificates = new ArrayList();
        certificates.addAll(sigData.getCertificates().getMatches(null));
        certificates.addAll(token.getCertificates().getMatches(null));
        Store certificateStore = new CollectionStore(certificates);

        AuthenticodeSignedDataGenerator generator = new AuthenticodeSignedDataGenerator();
        generator.addCertificates(certificateStore);
        generator.addSigners(new SignerInformationStore(Arrays.asList(signerInformation)));
        
        ASN1ObjectIdentifier contentType = new ASN1ObjectIdentifier(sigData.getSignedContentTypeOID());
        ASN1Encodable content = ASN1Sequence.getInstance(sigData.getSignedContent().getContent());
                
        return generator.generate(contentType, content);
    }

    protected abstract CMSSignedData timestamp(DigestAlgorithm algo, byte[] encryptedDigest) throws IOException, CMSException;

    /**
     * Returns the timestamper for the specified mode.
     */
    public static Timestamper create(TimestampingMode mode) {
        switch (mode) {
            case AUTHENTICODE:
                return new AuthenticodeTimestamper();
            case RFC3161:
                return new RFC3161Timestamper();
            default:
                throw new IllegalArgumentException("Unsupported timestamping mode: " + mode);
        }
    }
}
