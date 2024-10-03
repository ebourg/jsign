/**
 * Copyright 2017 Emmanuel Bourg
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
import java.util.List;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.util.encoders.Hex;

import static net.jsign.asn1.authenticode.AuthenticodeObjectIdentifiers.*;
import static org.junit.Assert.*;

public class SignatureAssert {

    public static void assertTimestamped(String message, CMSSignedData signedData) {
        SignerInformation signerInformation = signedData.getSignerInfos().getSigners().iterator().next();
        
        AttributeTable unsignedAttributes = signerInformation.getUnsignedAttributes();
        assertNotNull(message + " (missing unauthenticated attributes)", unsignedAttributes);
        
        boolean authenticode = isAuthenticode(signedData.getSignedContentTypeOID());
        Attribute authenticodeTimestampAttribute = unsignedAttributes.get(CMSAttributes.counterSignature);
        Attribute rfc3161TimestampAttribute = unsignedAttributes.get(authenticode ? SPC_RFC3161_OBJID : PKCSObjectIdentifiers.id_aa_signatureTimeStampToken);
        
        assertTrue(message + " (no counter signature attribute found)", authenticodeTimestampAttribute != null || rfc3161TimestampAttribute != null);
        
        if (authenticodeTimestampAttribute != null) {
            assertNotNull(message + " (counter signature attribute value is null)", authenticodeTimestampAttribute.getAttributeValues());
            assertTrue(message + " (counter signature attribute value is empty)", authenticodeTimestampAttribute.getAttributeValues().length > 0);
        } else {
            assertNotNull(message + " (counter signature attribute value is null)", rfc3161TimestampAttribute.getAttributeValues());
            assertTrue(message + " (counter signature attribute value is empty)", rfc3161TimestampAttribute.getAttributeValues().length > 0);
        }
    }

    public static void assertNotTimestamped(String message, CMSSignedData signedData) {
        SignerInformation signerInformation = signedData.getSignerInfos().getSigners().iterator().next();

        AttributeTable unsignedAttributes = signerInformation.getUnsignedAttributes();
        if (unsignedAttributes == null) {
            return;
        }
        
        boolean authenticode = isAuthenticode(signedData.getSignedContentTypeOID());
        Attribute authenticodeTimestampAttribute = unsignedAttributes.get(CMSAttributes.counterSignature);
        Attribute rfc3161TimestampAttribute = unsignedAttributes.get(authenticode ? SPC_RFC3161_OBJID : PKCSObjectIdentifiers.id_aa_signatureTimeStampToken);

        assertTrue(message + " (counter signature attribute found)", authenticodeTimestampAttribute == null && rfc3161TimestampAttribute == null);
    }

    public static void assertSigned(Signable signable, DigestAlgorithm... algorithms) throws IOException {
        List<CMSSignedData> signatures = signable.getSignatures();
        assertNotNull("list of signatures null", signatures);
        assertEquals("number of signatures", algorithms.length, signatures.size());

        for (int i = 0, signaturesSize = signatures.size(); i < signaturesSize; i++) {
            CMSSignedData signature = signatures.get(i);
            assertNotNull("signature " + i + " is null", signatures.get(0));

            // Check the version of the SignedData structure
            if (isAuthenticode(signature.getSignedContentTypeOID())) {
                assertEquals("Version of signature " + i, 1, signature.getVersion());
            }

            // Check the signature algorithm
            SignerInformation si = signature.getSignerInfos().getSigners().iterator().next();
            assertEquals("Digest algorithm of signature " + i, algorithms[i].oid, si.getDigestAlgorithmID().getAlgorithm());

            // Check if the signingTime attribute is present
            if (isAuthenticode(signature.getSignedContentTypeOID())) {
                assertNull("signingTime attribute found in signature " + i, signature.getSignerInfos().iterator().next().getSignedAttributes().get(CMSAttributes.signingTime));
            }
        }
    }

    public static void assertNotSigned(Signable signable) throws IOException {
        List<CMSSignedData> signatures = signable.getSignatures();
        assertNotNull("list of signatures null", signatures);
        assertTrue("signature found", signatures.isEmpty());
    }

    public static void assertUuidEquals(Signable signable, String expected) throws IOException {
        ASN1Sequence spcIndirectData = (ASN1Sequence) ((ASN1Sequence) signable.getSignatures().get(0).toASN1Structure().getContent()).getObjectAt(2);
        ASN1Sequence spcAttributeTypeAndOptionalValue = (ASN1Sequence) ((ASN1Sequence) ((ASN1TaggedObject) spcIndirectData.getObjectAt(1)).getExplicitBaseObject()).getObjectAt(0);
        ASN1Sequence spcSipInfo = (ASN1Sequence) spcAttributeTypeAndOptionalValue.getObjectAt(1);
        DEROctetString uuid = (DEROctetString) spcSipInfo.getObjectAt(1);

        assertEquals("Authenticode UUID", expected.toUpperCase().replaceAll("-", ""), Hex.toHexString(uuid.getOctets()).toUpperCase());
    }

    public static void assertSignedAttribute(String message, Signable signable, ASN1ObjectIdentifier oid) throws IOException {
        SignerInformation signerInformation = signable.getSignatures().get(0).getSignerInfos().getSigners().iterator().next();

        AttributeTable attributes = signerInformation.getSignedAttributes();
        assertNotNull(message + " (missing signed attributes)", attributes);

        Attribute attribute = attributes.get(oid);
        assertNotNull(message + " (missing " + oid + " attribute)", attribute);
    }
}
