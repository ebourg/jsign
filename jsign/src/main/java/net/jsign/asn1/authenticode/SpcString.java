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

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERTaggedObject;

/**
 * <pre>
 * SpcString ::= CHOICE {
 *     unicode                 [0] IMPLICIT BMPSTRING,
 *     ascii                   [1] IMPLICIT IA5STRING
 * } 
 * </pre>
 * 
 * @author Emmanuel Bourg
 * @since 1.0
 */
public class SpcString extends ASN1Object implements ASN1Choice {

    private DERBMPString unicode;
    private DERIA5String ascii;

    public SpcString(String string) {
        unicode = new DERBMPString(string);
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        if (unicode != null) {
            return new DERTaggedObject(false, 0, unicode);
        } else {
            return new DERTaggedObject(false, 1, ascii);
        }
    }
}
