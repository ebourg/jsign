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
import java.util.Collection;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.Store;

import net.jsign.DigestAlgorithm;
import net.jsign.asn1.authenticode.AuthenticodeSignedDataGenerator;

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
            throw new IllegalArgumentException("Invalid timestamping URL: " + tsaurl, e);
        }
    }

    /**
     * Timestamp the specified signature.
     * 
     * @param algo    the digest algorithm used for the timestamp
     * @param sigData the signed data to be timestamped
     * @return        the signed data with the timestamp added
     */
    public CMSSignedData timestamp(DigestAlgorithm algo, CMSSignedData sigData) throws IOException, CMSException {
        CMSSignedData token = timestamp(algo, getEncryptedDigest(sigData));
        return modifySignedData(sigData, getUnsignedAttributes(token), getExtraCertificates(token));
    }

    /**
     * Return the encrypted digest of the specified signature.
     */
    private byte[] getEncryptedDigest(CMSSignedData sigData) {
        SignerInformation signerInformation = sigData.getSignerInfos().getSigners().iterator().next();
        return signerInformation.toASN1Structure().getEncryptedDigest().getOctets();
    }

    /**
     * Return the certificate chain of the timestamping authority if it isn't included
     * with the counter signature in the unsigned attributes.
     */
    protected Collection<X509CertificateHolder> getExtraCertificates(CMSSignedData token) {
        return null;
    }

    /**
     * Return the counter signature to be added as an unsigned attribute.
     */
    protected abstract AttributeTable getUnsignedAttributes(CMSSignedData token);

    protected CMSSignedData modifySignedData(CMSSignedData sigData, AttributeTable unsignedAttributes, Collection<X509CertificateHolder> extraCertificates) throws IOException, CMSException {
        SignerInformation signerInformation = sigData.getSignerInfos().getSigners().iterator().next();
        signerInformation = SignerInformation.replaceUnsignedAttributes(signerInformation, unsignedAttributes);
        
        Collection<X509CertificateHolder> certificates = new ArrayList<X509CertificateHolder>();
        certificates.addAll(sigData.getCertificates().getMatches(null));
        if (extraCertificates != null) {
            certificates.addAll(extraCertificates);
        }
        Store<X509CertificateHolder> certificateStore = new CollectionStore<X509CertificateHolder>(certificates);
        
        AuthenticodeSignedDataGenerator generator = new AuthenticodeSignedDataGenerator();
        generator.addCertificates(certificateStore);
        generator.addSigners(new SignerInformationStore(signerInformation));
        
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
