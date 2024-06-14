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
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.apache.commons.io.HexDump;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.selector.X509CertificateHolderSelector;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.PKCS7ProcessableObject;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.Store;

import net.jsign.DigestAlgorithm;
import net.jsign.asn1.authenticode.AuthenticodeObjectIdentifiers;
import net.jsign.asn1.authenticode.AuthenticodeSignedDataGenerator;

/**
 * Interface for a timestamping service.
 * 
 * @author Emmanuel Bourg
 * @since 1.3
 */
public abstract class Timestamper {

    protected Logger log = Logger.getLogger(getClass().getName());

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
            if (count > 0) {
                // pause before the next attempt
                try {
                    long pause = retryWait * 1000L;
                    log.fine("Timestamping failed, retrying in " + pause / 1000 + " seconds");
                    Thread.sleep(pause);
                } catch (InterruptedException ie) {
                }
            }
            try {
                tsaurl = tsaurls.get(count % tsaurls.size());
                log.fine("Timestamping with " + tsaurl);
                long t0 = System.currentTimeMillis();
                token = timestamp(algo, getEncryptedDigest(sigData));
                long t1 = System.currentTimeMillis();
                log.fine("Timestamping completed in " + (t1 - t0) + " ms");
                break;
            } catch (TimestampingException | IOException e) {
                exception.addSuppressed(e);
            }
            count++;
        }
        
        if (token == null) {
            throw exception;
        }
        
        return modifySignedData(sigData, getCounterSignature(token), getExtraCertificates(token));
    }

    byte[] post(URL url, byte[] data, Map<String, String> headers) throws IOException {
        log.finest("POST " + url);

        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setConnectTimeout(10000);
        conn.setReadTimeout(10000);
        conn.setDoOutput(true);
        conn.setDoInput(true);
        conn.setUseCaches(false);
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-length", String.valueOf(data.length));
        conn.setRequestProperty("User-Agent", "Transport");
        for (Map.Entry<String, String> header : headers.entrySet()) {
            conn.setRequestProperty(header.getKey(), header.getValue());
        }

        if (log.isLoggable(Level.FINEST)) {
            for (String header : conn.getRequestProperties().keySet()) {
                log.finest(header + ": " + conn.getRequestProperty(header));
            }
            log("Content", data);
        }

        conn.getOutputStream().write(data);
        conn.getOutputStream().flush();

        for (String header : conn.getHeaderFields().keySet()) {
            log.finest((header != null ? header + ": " : "") + conn.getHeaderField(header));
        }
        if (conn.getResponseCode() >= 400) {
            byte[] error = conn.getErrorStream() != null ? IOUtils.toByteArray(conn.getErrorStream()) : new byte[0];
            if (conn.getErrorStream() != null) {
                log("Error", error);
            }
            throw new IOException("Unable to complete the timestamping due to HTTP error: " + conn.getResponseCode() + " - " + conn.getResponseMessage());
        }

        byte[] content = IOUtils.toByteArray(conn.getInputStream());
        log("Content", content);
        
        return content;
    }

    private void log(String description, byte[] data) throws IOException {
        if (log.isLoggable(Level.FINEST)) {
            log.finest(description + ":");
            StringBuffer out = new StringBuffer();
            HexDump.dump(data, 0, out, 0, data.length);
            log.finest(out.toString());
        }
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
     * @return the attribute wrapping the timestamp
     * @since 5.0
     */
    protected abstract Attribute getCounterSignature(CMSSignedData token);

    /**
     * Return the counter signature to be added as an unsigned attribute.
     *
     * @param token the timestamp
     * @return the attribute wrapping the timestamp
     * @deprecated use {@link #getCounterSignature(CMSSignedData)} instead
     */
    @Deprecated
    protected AttributeTable getUnsignedAttributes(CMSSignedData token) {
        return new AttributeTable(getCounterSignature(token));
    }

    @Deprecated
    protected CMSSignedData modifySignedData(CMSSignedData sigData, AttributeTable counterSignature, Collection<X509CertificateHolder> extraCertificates) throws IOException, CMSException {
        return modifySignedData(sigData, Attribute.getInstance(counterSignature.toASN1EncodableVector().get(0)), extraCertificates);
    }

    protected CMSSignedData modifySignedData(CMSSignedData sigData, Attribute counterSignature, Collection<X509CertificateHolder> extraCertificates) throws IOException, CMSException {
        SignerInformation signerInformation = sigData.getSignerInfos().getSigners().iterator().next();
        AttributeTable unsignedAttributes = signerInformation.getUnsignedAttributes();
        if (unsignedAttributes == null) {
            unsignedAttributes = new AttributeTable(counterSignature);
        } else {
            unsignedAttributes = unsignedAttributes.add(counterSignature.getAttrType(), counterSignature.getAttrValues().getObjectAt(0));
        }
        signerInformation = SignerInformation.replaceUnsignedAttributes(signerInformation, unsignedAttributes);
        
        // add the new timestamping authority certificates
        Collection<X509CertificateHolder> certificates = new ArrayList<>(sigData.getCertificates().getMatches(null));
        if (extraCertificates != null) {
            for (X509CertificateHolder certificate : extraCertificates) {
                X509CertificateHolderSelector selector = new X509CertificateHolderSelector(certificate.getIssuer(), certificate.getSerialNumber());
                if (sigData.getCertificates().getMatches(selector).isEmpty()) {
                    certificates.add(certificate);
                }
            }
        }
        Store<X509CertificateHolder> certificateStore = new CollectionStore<>(certificates);

        // get the signed content (CMSSignedData.getSignedContent() has a null content when loading the signature back from the file)
        byte[] encoded = sigData.toASN1Structure().getContent().toASN1Primitive().getEncoded("DER");
        SignedData signedData = SignedData.getInstance(new ASN1InputStream(encoded).readObject());
        ContentInfo content = signedData.getEncapContentInfo();
        PKCS7ProcessableObject signedContent = new PKCS7ProcessableObject(content.getContentType(), content.getContent());

        boolean authenticode = AuthenticodeObjectIdentifiers.isAuthenticode(sigData.getSignedContentTypeOID());
        CMSSignedDataGenerator generator = authenticode ? new AuthenticodeSignedDataGenerator() : new CMSSignedDataGenerator();
        generator.addCertificates(certificateStore);
        generator.addSigners(new SignerInformationStore(signerInformation));
        
        return generator.generate(signedContent, true);
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
