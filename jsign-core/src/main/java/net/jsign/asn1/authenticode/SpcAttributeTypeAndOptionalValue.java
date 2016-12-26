/**
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

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
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

    private ASN1ObjectIdentifier type;
    private ASN1Object value;

    public SpcAttributeTypeAndOptionalValue(ASN1ObjectIdentifier type, ASN1Object value) {
        this.type = type;
        this.value = value;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(type);
        if (value != null) {
            v.add(value);
        }
        
        return new BERSequence(v);
    }
}
