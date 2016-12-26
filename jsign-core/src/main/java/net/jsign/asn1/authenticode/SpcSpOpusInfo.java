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
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.BERSequence;
import org.bouncycastle.asn1.DERTaggedObject;

/**
 * <pre>
 * SpcSpOpusInfo ::= SEQUENCE {
 *     programName             [0] EXPLICIT SpcString OPTIONAL,
 *     moreInfo                [1] EXPLICIT SpcLink OPTIONAL,
 * }
 * </pre>
 * 
 * @author Emmanuel Bourg
 * @since 1.0
 */
public class SpcSpOpusInfo extends ASN1Object {

    /**
     * This field contains the program description:
     * - If publisher chooses not to specify a description, the SpcString structure contains a zero-length program name.
     * - If the publisher chooses to specify a description, the SpcString structure contains a Unicode string.
     */
    private SpcString programName;

    /**
     * This field is set to an SPCLink structure that contains a URL for a Web
     * site with more information about the signer. The URL is an ASCII string.
     */
    private SpcLink moreInfo;

    public SpcSpOpusInfo(String programName, String url) {
        if (programName != null) {
            this.programName = new SpcString(programName);
        }
        if (url != null) {
            this.moreInfo = new SpcLink(url);
        }
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        
        if (programName != null) {
            v.add(new DERTaggedObject(true, 0, programName));
        }
        
        if (moreInfo != null) {
            v.add(new DERTaggedObject(true, 1, moreInfo));
        }
        
        return new BERSequence(v);
    }
}
