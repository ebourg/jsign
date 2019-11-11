/*
 * Copyright 2019 Björn Kautler
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
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.BERSequence;
import org.bouncycastle.asn1.DEROctetString;

public class SpcSipinfo extends ASN1Object {
    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();

        // uint cbStruct (WINTRUST_BLOB_INFO struct size)
        v.add(new ASN1Integer(65536));

        // GUID gSubject (The GUID of the PowerShell SIP)
        v.add(new DEROctetString(new byte[] {
                (byte) 0x1f,
                (byte) 0xcc,
                (byte) 0x3b,
                (byte) 0x60,
                (byte) 0x59,
                (byte) 0x4b,
                (byte) 0x08,
                (byte) 0x4e,
                (byte) 0xb7,
                (byte) 0x24,
                (byte) 0xd2,
                (byte) 0xc6,
                (byte) 0x29,
                (byte) 0x7e,
                (byte) 0xf3,
                (byte) 0x51
        }));

        // We set the following five as 0 because PowerShell does the same on signing

        // string pcwszDisplayName (fileName)
        v.add(new ASN1Integer(0));

        // uint cbMemObject (contentBytes.Length)
        v.add(new ASN1Integer(0));

        // System.IntPtr pbMemObject (Marshal.AllocCoTaskMem(contentBytes.Length)))
        v.add(new ASN1Integer(0));

        // uint cbMemSignedMsg
        v.add(new ASN1Integer(0));

        // System.IntPtr pbMemSignedMsg
        v.add(new ASN1Integer(0));

        return new BERSequence(v);
    }
}
