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
import java.util.List;

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

    /** The URL of the current timestamping service */
    protected URL tsaurl;

    /** The URLs of the timestamping services */
    protected List<URL> tsaurls;

    /** The number of retries */
    protected int retries = 3;

    /** Seconds to wait between retries */
    protected int retryWait = 10;

    /**
     * Set the URL of the timestamping service.
     *
     * @param tsaurl the URL of the timestamping service
     */
    public void setURL(String tsaurl) {
        setURLs(tsaurl);
    }

    /**
     * Set the URLs of the timestamping services.
     * 
     * @param tsaurls the URLs of the timestamping services
     * @since 2.0
     */
    public void setURLs(String... tsaurls) {
        List<URL> urls = new ArrayList<>();
        for (String tsaurl : tsaurls) {
            try {
                urls.add(new URL(tsaurl));
            } catch (MalformedURLException e) {
                throw new IllegalArgumentException("Invalid timestamping URL: " + tsaurl, e);
            }
        }
        this.tsaurls = urls;
    }

    /**
     * Set the number of retries.
     * 
     * @param retries the number of retries
     */
    public void setRetries(int retries) {
        this.retries = retries;
    }

    /**
     * Set the number of seconds to wait between retries.
     * 
     * @param retryWait the wait time between retries (in seconds)
     */
    public void setRetryWait(int retryWait) {
        this.retryWait = retryWait;
    }

    /**
     * Timestamp the specified signature.
     * 
     * @param algo    the digest algorithm used for the timestamp
     * @param sigData the signed data to be timestamped
     * @return        the signed data with the timestamp added
     * @throws IOException if an I/O error occurs
     * @throws TimestampingException if the timestamping keeps failing after the configured number of attempts
     * @throws CMSException if the signature cannot be generated
     */
    public CMSSignedData timestamp(DigestAlgorithm algo, CMSSignedData sigData) throws TimestampingException, IOException, CMSException {
        CMSSignedData token = null;
        
        // Retry the timestamping and failover other services if a TSA is unavailable for a short period of time
        int attempts = Math.max(retries, tsaurls.size());
        TimestampingException exception = new TimestampingException("Unable to complete the timestamping after " + attempts + " attempt" + (attempts > 1 ? "s" : ""));
        int count = 0;
        while (count < Math.max(retries, tsaurls.size())) {
            try {
                tsaurl = tsaurls.get(count % tsaurls.size());
                token = timestamp(algo, getEncryptedDigest(sigData));
                break;
            } catch (TimestampingException | IOException e) {
                exception.addSuppressed(e);
            }

            // pause before the next attempt
            try {
                Thread.sleep(retryWait * 1000L);
                count++;
            } catch (InterruptedException ie) {
            }
        }
        
        if (token == null) {
            throw exception;
        }
        
        return modifySignedData(sigData, getUnsignedAttributes(token), getExtraCertificates(token));
    }

    /**
     * Return the encrypted digest of the specified signature.
     * 
     * @param sigData the signature
     * @return the encrypted digest
     */
    private byte[] getEncryptedDigest(CMSSignedData sigData) {
        SignerInformation signerInformation = sigData.getSignerInfos().getSigners().iterator().next();
        return signerInformation.toASN1Structure().getEncryptedDigest().getOctets();
    }

    /**
     * Return the certificate chain of the timestamping authority if it isn't included
     * with the counter signature in the unsigned attributes.
     * 
     * @param token the timestamp
     * @return the certificate chain of the timestamping authority
     */
    protected Collection<X509CertificateHolder> getExtraCertificates(CMSSignedData token) {
        return null;
    }

    /**
     * Return the counter signature to be added as an unsigned attribute.
     * 
     * @param token the timestamp
     * @return the unsigned attribute wrapping the timestamp
     */
    protected abstract AttributeTable getUnsignedAttributes(CMSSignedData token);

    protected CMSSignedData modifySignedData(CMSSignedData sigData, AttributeTable unsignedAttributes, Collection<X509CertificateHolder> extraCertificates) throws IOException, CMSException {
        SignerInformation signerInformation = sigData.getSignerInfos().getSigners().iterator().next();
        signerInformation = SignerInformation.replaceUnsignedAttributes(signerInformation, unsignedAttributes);
        
        Collection<X509CertificateHolder> certificates = new ArrayList<>();
        certificates.addAll(sigData.getCertificates().getMatches(null));
        if (extraCertificates != null) {
            certificates.addAll(extraCertificates);
        }
        Store<X509CertificateHolder> certificateStore = new CollectionStore<>(certificates);
        
        AuthenticodeSignedDataGenerator generator = new AuthenticodeSignedDataGenerator();
        generator.addCertificates(certificateStore);
        generator.addSigners(new SignerInformationStore(signerInformation));
        
        ASN1ObjectIdentifier contentType = new ASN1ObjectIdentifier(sigData.getSignedContentTypeOID());
        ASN1Encodable content = ASN1Sequence.getInstance(sigData.getSignedContent().getContent());
                
        return generator.generate(contentType, content);
    }

    protected abstract CMSSignedData timestamp(DigestAlgorithm algo, byte[] encryptedDigest) throws IOException, TimestampingException;

    /**
     * Returns the timestamper for the specified mode.
     * 
     * @param mode the timestamping mode
     * @return a new timestamper for the specified mode
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
