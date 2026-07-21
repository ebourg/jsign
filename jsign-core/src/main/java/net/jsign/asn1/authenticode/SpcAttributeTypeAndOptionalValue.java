/*
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

package net.jsign.asn1.authenticode;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.BERSequence;

/**
 * <pre>
 * SpcAttributeTypeAndOptionalValue ::= SEQUENCE {
 *     type                    OBJECT IDENTIFIER,
 *     value                   ANY DEFINED BY type OPTIONAL
 * }
 * </pre>
 * 
 * @author Emmanuel Bourg
 * @since 1.0
 */
public class SpcAttributeTypeAndOptionalValue extends ASN1Object {

    private final ASN1ObjectIdentifier type;
    private final ASN1Encodable value;

    public SpcAttributeTypeAndOptionalValue(ASN1ObjectIdentifier type, ASN1Encodable value) {
        this.type = type;
        this.value = value;
    }

    public ASN1ObjectIdentifier getType() {
        return type;
    }

    public ASN1Encodable getValue() {
        return value;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(type);
        if (value != null) {
            v.add(value);
        }
        
        return new BERSequence(v);
    }

    public static SpcAttributeTypeAndOptionalValue parse(ASN1Sequence sequence) {
        ASN1ObjectIdentifier type = ASN1ObjectIdentifier.getInstance(sequence.getObjectAt(0));
        ASN1Encodable value = null;
        if (sequence.size() > 1) {
            if (type.equals(AuthenticodeObjectIdentifiers.SPC_SIPINFO_OBJID)) {
                value = SpcSipInfo.parse(sequence.getObjectAt(1));
            } else if (type.equals(AuthenticodeObjectIdentifiers.SPC_CAB_DATA_OBJID)
                    || type.equals(AuthenticodeObjectIdentifiers.SPC_PE_IMAGE_DATA_OBJID)) {
                value = SpcPeImageData.parse(sequence.getObjectAt(1));
            } else {
                value = sequence.getObjectAt(1);
            }
        }
        
        return new SpcAttributeTypeAndOptionalValue(type, value);
    }
}
