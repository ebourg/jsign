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
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;

import net.jsign.asn1.authenticode.AuthenticodeObjectIdentifiers;

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
                SignerInformation signerInformation = signature.getSignerInfos().getSigners().iterator().next();
                AttributeTable unsignedAttributes = signerInformation.getUnsignedAttributes();
                if (unsignedAttributes != null) {
                    Attribute nestedSignatures = unsignedAttributes.get(AuthenticodeObjectIdentifiers.SPC_NESTED_SIGNATURE_OBJID);
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
}
