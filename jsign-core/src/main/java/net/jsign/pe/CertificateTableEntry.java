/**
 * Copyright 2016 Emmanuel Bourg
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

package net.jsign.pe;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSSignedData;

/**
 * Entry of the certificate table.
 * 
 * @author Emmanuel Bourg
 * @since 1.3
 */
public class CertificateTableEntry {

    private int size;
    private int revision;
    private int type;
    private byte[] content;
    private CMSSignedData signature;

    CertificateTableEntry(PEFile peFile, long index) {
        size = (int) peFile.readDWord(index, 0);
        revision = peFile.readWord(index, 4);
        type = peFile.readWord(index, 6);
        content = new byte[size - 8];
        peFile.read(content, index, 8);
    }

    public CertificateTableEntry(CMSSignedData signature) throws IOException {
        setSignature(signature);
    }

    public int getSize() {
        return size;
    }

    public CMSSignedData getSignature() throws CMSException {
        if (type != CertificateType.PKCS_SIGNED_DATA.getValue()) {
            throw new UnsupportedOperationException("Unsupported certificate type: " + type);
        }
        
        if (revision != 0x0200) {
            throw new UnsupportedOperationException("Unsupported certificate revision: " + revision);
        }
        
        if (signature == null) {
            try {
                signature = new CMSSignedData((CMSProcessable) null, ContentInfo.getInstance(new ASN1InputStream(content).readObject()));
            } catch (IOException e) {
                throw new IllegalArgumentException("Failed to construct ContentInfo from byte[]: ", e);
            }
        }
        
        return signature;
    }

    public void setSignature(CMSSignedData signature) throws IOException {
        this.signature = signature;
        byte[] content = signature.toASN1Structure().getEncoded("DER");
        this.content = pad(content, 8);
        this.size = this.content.length + 8;
        this.type = CertificateType.PKCS_SIGNED_DATA.getValue();
    }

    private byte[] pad(byte[] data, int multiple) {
        if (data.length % multiple == 0) {
            return data;
        } else {
            byte[] copy = new byte[data.length + (multiple - data.length % multiple)];
            System.arraycopy(data, 0, copy, 0, data.length);
            return copy;
        }
    }

    public byte[] toBytes() {
        ByteBuffer buffer = ByteBuffer.allocate(size);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        buffer.putInt(buffer.limit());
        buffer.putShort((short) 0x0200);
        buffer.putShort(CertificateType.PKCS_SIGNED_DATA.getValue());
        buffer.put(content);
        
        return buffer.array();
    }
}
