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

package net.jsign.asn1.authenticode;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;

/**
 * <pre>
 * SpcUuid ::= OCTETSTRING
 * </pre>
 * 
 * @author Emmanuel Bourg
 * @since 1.3
 */
public class SpcUuid  extends ASN1Object {

    private static final DEROctetString UUID = new DEROctetString(new BigInteger("a6b586d5b4a12466ae05a217da8e60d6", 16).toByteArray());

    @Override
    public ASN1Primitive toASN1Primitive() {
        return UUID;
    }
}
