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
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERTaggedObject;

/**
 * <pre>
 * SpcLink ::= CHOICE {
 *     url                     [0] IMPLICIT IA5STRING,
 *     moniker                 [1] IMPLICIT SpcSerializedObject,
 *     file                    [2] EXPLICIT SpcString
 * }
 * </pre>
 * 
 * @author Emmanuel Bourg
 * @since 1.0
 */
public class SpcLink extends ASN1Object implements ASN1Choice {

    private DERIA5String url;
    private SpcSerializedObject moniker;
    private SpcString file = new SpcString("");

    public SpcLink() {
    }

    public SpcLink(String url) {
        this.url = new DERIA5String(url);
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        if (url != null) {
            return new DERTaggedObject(false, 0, url);
        } else if (moniker != null) {
            return new DERTaggedObject(false, 1, moniker);
        } else {
            return new DERTaggedObject(false, 2, file);
        }        
    }
}
