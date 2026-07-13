/*
 * Copyright 2024 Emmanuel Bourg
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

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.NoSuchElementException;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.selector.X509CertificateHolderSelector;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.util.Store;

import static net.jsign.asn1.authenticode.AuthenticodeObjectIdentifiers.*;

/**
 * Helper class for working with signatures.
 *
 * @since 7.0
 */
public class SignatureUtils {

    /**
     * Parse the specified signature.
     *
     * @param signature the signature to analyze
     * @since 7.5
     */
    public static CMSSignedData getSignature(byte[] signature) throws IOException {
        try {
            return new CMSSignedData(signature);
        } catch (CMSException | IllegalArgumentException | IllegalStateException | NoSuchElementException | ClassCastException | StackOverflowError e) {
            // Bouncy Castle can throw a wide range of exceptions when parsing a signature, so we wrap them all in an IOException
            throw new IOException("Malformed signature", e);
        }
    }

    /**
     * Parse the specified signature and return the nested Authenticode signatures.
     *
     * @param signature the signature to analyze
     */
    public static List<CMSSignedData> getSignatures(byte[] signature) throws IOException {
        return getSignatures(getSignature(signature));
    }

    /**
     * Extract the nested Authenticode signatures from the specified signature.
     *
     * @param signature the signature to analyze
     * @return the list of signatures (the first one is the parent signature without nested signatures)
     */
    public static List<CMSSignedData> getSignatures(CMSSignedData signature) throws IOException {
        List<CMSSignedData> signatures = new ArrayList<>();

        try {
            if (signature != null) {
                signatures.add(signature);
                signatures.set(0, SignatureUtils.removeNestedSignatures(signature));

                // look for nested signatures
                Attribute nestedSignatures = getUnsignedAttribute(signature, SPC_NESTED_SIGNATURE_OBJID);
                if (nestedSignatures != null) {
                    for (ASN1Encodable nestedSignature : nestedSignatures.getAttrValues()) {
                        signatures.add(new CMSSignedData(nestedSignature.toASN1Primitive().getEncoded()));
                    }
                }
            }
        } catch (CMSException e) {
            throw new IOException(e);
        }

        return signatures;
    }

    /**
     * Embed a signature as an unsigned attribute of an existing signature.
     *
     * @param parent    the root signature hosting the nested secondary signature
     * @param children  the additional signature to nest inside the root signature
     * @return the signature combining the specified signatures
     */
    static CMSSignedData addNestedSignature(CMSSignedData parent, boolean replace, CMSSignedData... children) {
        SignerInformation signerInformation = parent.getSignerInfos().iterator().next();

        AttributeTable unsignedAttributes = signerInformation.getUnsignedAttributes();
        if (unsignedAttributes == null) {
            unsignedAttributes = new AttributeTable(new DERSet());
        }

        Attribute nestedSignaturesAttribute = unsignedAttributes.get(SPC_NESTED_SIGNATURE_OBJID);
        ASN1EncodableVector nestedSignatures = new ASN1EncodableVector();
        if (nestedSignaturesAttribute != null && !replace) {
            // keep the previous nested signatures
            for (ASN1Encodable nestedSignature : nestedSignaturesAttribute.getAttrValues()) {
                nestedSignatures.add(nestedSignature);
            }
        }

        // append the new signatures
        for (CMSSignedData nestedSignature : children) {
            nestedSignatures.add(nestedSignature.toASN1Structure());
        }

        // replace the nested signatures attribute
        ASN1EncodableVector attributes = unsignedAttributes.remove(SPC_NESTED_SIGNATURE_OBJID).toASN1EncodableVector();
        attributes.add(new Attribute(SPC_NESTED_SIGNATURE_OBJID, new DERSet(nestedSignatures)));

        unsignedAttributes = new AttributeTable(attributes);

        signerInformation = SignerInformation.replaceUnsignedAttributes(signerInformation, unsignedAttributes);
        return CMSSignedData.replaceSigners(parent, new SignerInformationStore(signerInformation));
    }

    /**
     * Remove the nested signatures from the specified signature.
     *
     * @param signature the signature to modify
     * @return the signature without nested signatures
     */
    static CMSSignedData removeNestedSignatures(CMSSignedData signature) {
        return removeUnsignedAttributes(signature, SPC_NESTED_SIGNATURE_OBJID);
    }

    /**
     * Tells if the specified signature is timestamped.
     *
     * @param signature the signature to check
     */
    static boolean isTimestamped(CMSSignedData signature) {
        boolean authenticode = isAuthenticode(signature.getSignedContentTypeOID());
        Attribute authenticodeTimestampAttribute = getUnsignedAttribute(signature, CMSAttributes.counterSignature);
        Attribute rfc3161TimestampAttribute = getUnsignedAttribute(signature, authenticode ? SPC_RFC3161_OBJID : PKCSObjectIdentifiers.id_aa_signatureTimeStampToken);
        return authenticodeTimestampAttribute != null || rfc3161TimestampAttribute != null;
    }

    /**
     * Removes the timestamp from the specified signature.
     *
     * @param signature the signature to modify
     */
    static CMSSignedData removeTimestamp(CMSSignedData signature) {
        // todo remove the TSA certificates from the certificate store

        return removeUnsignedAttributes(signature,
                CMSAttributes.counterSignature,
                PKCSObjectIdentifiers.id_aa_signatureTimeStampToken,
                SPC_RFC3161_OBJID);
    }

    /**
     * Remove the specified unsigned attributes from the signature.
     *
     * @param signature the signature to modify
     * @param oids the OIDs of the attributes to remove
     * @return the modified signature
     */
    static CMSSignedData removeUnsignedAttributes(CMSSignedData signature, ASN1ObjectIdentifier... oids) {
        SignerInformation signerInformation = signature.getSignerInfos().iterator().next();

        AttributeTable unsignedAttributes = signerInformation.getUnsignedAttributes();
        if (unsignedAttributes == null) {
            return signature;
        }

        for (ASN1ObjectIdentifier oid : oids) {
            unsignedAttributes = unsignedAttributes.remove(oid);
        }

        signerInformation = SignerInformation.replaceUnsignedAttributes(signerInformation, unsignedAttributes);
        return CMSSignedData.replaceSigners(signature, new SignerInformationStore(signerInformation));
    }

    /**
     * Returns the digest info of the signature.
     *
     * @since 7.5
     */
    static DigestInfo getDigestInfo(CMSSignedData signature) {
        if (SPC_INDIRECT_DATA_OBJID.equals(signature.getSignedContent().getContentType())) {
            ASN1Sequence indirectData = (ASN1Sequence) signature.getSignedContent().getContent();
            return DigestInfo.getInstance(indirectData.getObjectAt(1));
        }

        if (PKCSObjectIdentifiers.data.equals(signature.getSignedContent().getContentType())) {
            // the data is assumed to be the digest of the file with the same algorithm as the signature
            SignerInformation signer = signature.getSignerInfos().iterator().next();
            AlgorithmIdentifier digestAlgorithm = signer.getDigestAlgorithmID();
            return new DigestInfo(digestAlgorithm, (byte[]) signature.getSignedContent().getContent());
        }

        return null;
    }

    /**
     * Returns the timestamp signer information.
     *
     * @since 7.5
     */
    static SignerInformation getCounterSigner(CMSSignedData signature) throws CMSException {
        SignerInformation signer = signature.getSignerInfos().iterator().next();

        Collection<SignerInformation> counterSigners = Collections.emptyList();

        Attribute timestampAttribute = getUnsignedAttribute(signature, CMSAttributes.counterSignature);
        if (timestampAttribute != null) {
            counterSigners = signer.getCounterSignatures().getSigners();
        }

        timestampAttribute  = getUnsignedAttribute(signature, SPC_RFC3161_OBJID);
        if (timestampAttribute == null) {
            timestampAttribute = getUnsignedAttribute(signature, PKCSObjectIdentifiers.id_aa_signatureTimeStampToken);
        }
        if (timestampAttribute != null) {
            CMSSignedData signedData = new CMSSignedData(ContentInfo.getInstance(timestampAttribute.getAttrValues().getObjectAt(0)));
            counterSigners = signedData.getSignerInfos().getSigners();
        }

        return !counterSigners.isEmpty() ? counterSigners.iterator().next() : null;
    }

    /**
     * Returns the signing time of the timestamp.
     *
     * @since 7.5
     */
    static Date getTimestampDate(CMSSignedData signature) throws CMSException {
        SignerInformation counterSigner = getCounterSigner(signature);
        if (counterSigner != null) {
            Attribute signingTime = counterSigner.getSignedAttributes().get(CMSAttributes.signingTime);
            if (signingTime != null) {
                return Time.getInstance(signingTime.getAttrValues().getObjectAt(0)).getDate();
            }
        }

        return null;
    }

    /**
     * Returns the certificate of the timestamp.
     *
     * @since 7.5
     */
    static X509CertificateHolder getTimestampCertificate(CMSSignedData signature) throws CMSException {
        SignerInformation counterSigner = getCounterSigner(signature);
        if (counterSigner == null) {
            return null;
        }

        Store<X509CertificateHolder> certificates = signature.getCertificates();
        AttributeTable unsignedAttributes = signature.getSignerInfos().iterator().next().getUnsignedAttributes();
        Attribute timestampAttribute  = unsignedAttributes.get(SPC_RFC3161_OBJID);
        if (timestampAttribute != null) {
            CMSSignedData signedData = new CMSSignedData(ContentInfo.getInstance(timestampAttribute.getAttrValues().getObjectAt(0)));
            certificates = signedData.getCertificates();
        }

        X509CertificateHolderSelector selector = new X509CertificateHolderSelector(counterSigner.getSID().getIssuer(), counterSigner.getSID().getSerialNumber());

        Collection<X509CertificateHolder> matches = certificates.getMatches(selector);
        return !matches.isEmpty() ? matches.iterator().next() : null;
    }


    /**
     * Returns the value of the unsigned tag
     *
     * @param signature the CMS signed data
     * @return the value of the unsigned tag (ASN1UTF8String or ASN1OctetString), or null if not found
     * @since 7.5
     */
    static ASN1Encodable getTag(CMSSignedData signature) throws IOException {
        Attribute attribute = getUnsignedAttribute(signature, JSIGN_UNSIGNED_DATA_OBJID);
        if (attribute == null) {
            attribute = getUnsignedAttribute(signature, new ASN1ObjectIdentifier("1.3.6.1.4.1.42921.1.2.1")); // Dropbox OID used by osslsigncode
        }

        return attribute != null ? attribute.getAttrValues().getObjectAt(0) : null;
    }

    /**
     * Returns the specified unsigned attribute from the signature.
     *
     * @param signature the signature
     * @param oid       the object identifier of the attribute
     * @return the unsigned attribute, or null if not found
     * @since 7.5
     */
    static Attribute getUnsignedAttribute(CMSSignedData signature, ASN1ObjectIdentifier oid) {
        SignerInformation signer = signature.getSignerInfos().iterator().next();

        AttributeTable unsignedAttributes = signer.getUnsignedAttributes();
        if (unsignedAttributes == null) {
            return null;
        }

        return unsignedAttributes.get(oid);
    }
}
