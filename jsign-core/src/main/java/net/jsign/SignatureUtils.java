/**
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
import java.util.List;
import java.util.NoSuchElementException;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;

import static net.jsign.asn1.authenticode.AuthenticodeObjectIdentifiers.*;

/**
 * Helper class for working with signatures.
 *
 * @since 7.0
 */
public class SignatureUtils {

    /**
     * Parse the specified signature and return the nested Authenticode signatures.
     *
     * @param signature the signature to analyze
     */
    public static List<CMSSignedData> getSignatures(byte[] signature) throws IOException {
        try (ASN1InputStream in = new ASN1InputStream(signature)) {
            CMSSignedData signedData = new CMSSignedData((CMSProcessable) null, ContentInfo.getInstance(in.readObject()));
            return getSignatures(signedData);
        } catch (CMSException | IllegalArgumentException | IllegalStateException | NoSuchElementException | ClassCastException | StackOverflowError e) {
            throw new IOException(e);
        }
    }

    /**
     * Extract the nested Authenticode signatures from the specified signature.
     *
     * @param signature the signature to analyze
     */
    public static List<CMSSignedData> getSignatures(CMSSignedData signature) throws IOException {
        List<CMSSignedData> signatures = new ArrayList<>();

        try {
            if (signature != null) {
                signatures.add(signature);

                // look for nested signatures
                SignerInformation signerInformation = signature.getSignerInfos().iterator().next();
                AttributeTable unsignedAttributes = signerInformation.getUnsignedAttributes();
                if (unsignedAttributes != null) {
                    Attribute nestedSignatures = unsignedAttributes.get(SPC_NESTED_SIGNATURE_OBJID);
                    if (nestedSignatures != null) {
                        for (ASN1Encodable nestedSignature : nestedSignatures.getAttrValues()) {
                            signatures.add(new CMSSignedData((CMSProcessable) null, ContentInfo.getInstance(nestedSignature)));
                        }
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
     * Tells if the specified signature is timestamped.
     *
     * @param signature the signature to check
     */
    static boolean isTimestamped(CMSSignedData signature) {
        SignerInformation signerInformation = signature.getSignerInfos().iterator().next();

        AttributeTable unsignedAttributes = signerInformation.getUnsignedAttributes();
        if (unsignedAttributes == null) {
            return false;
        }

        boolean authenticode = isAuthenticode(signature.getSignedContentTypeOID());
        Attribute authenticodeTimestampAttribute = unsignedAttributes.get(CMSAttributes.counterSignature);
        Attribute rfc3161TimestampAttribute = unsignedAttributes.get(authenticode ? SPC_RFC3161_OBJID : PKCSObjectIdentifiers.id_aa_signatureTimeStampToken);
        return authenticodeTimestampAttribute != null || rfc3161TimestampAttribute != null;
    }

    /**
     * Removes the timestamp from the specified signature.
     *
     * @param signature the signature to modify
     */
    static CMSSignedData removeTimestamp(CMSSignedData signature) {
        SignerInformation signerInformation = signature.getSignerInfos().iterator().next();

        AttributeTable unsignedAttributes = signerInformation.getUnsignedAttributes();
        if (unsignedAttributes == null) {
            return signature;
        }

        unsignedAttributes = unsignedAttributes.remove(CMSAttributes.counterSignature);
        unsignedAttributes = unsignedAttributes.remove(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken);
        unsignedAttributes = unsignedAttributes.remove(SPC_RFC3161_OBJID);

        // todo remove the TSA certificates from the certificate store

        signerInformation = SignerInformation.replaceUnsignedAttributes(signerInformation, unsignedAttributes);
        return CMSSignedData.replaceSigners(signature, new SignerInformationStore(signerInformation));
    }
}
