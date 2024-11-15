/**
 * Copyright 2023 Emmanuel Bourg
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

package net.jsign.navx;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSSignedData;

import static java.nio.ByteOrder.*;

/**
 * NAVX signature block
 *
 *  <pre>
 *  signature                       4 bytes  (NXSB)
 *  CMS Signed Data                 (variable size)
 *  offset of the signature block   4 bytes
 *  signature                       4 bytes  (NXSB)
 *  </pre>
 *
 * @since 6.0
 */
class NAVXSignatureBlock {

    public static final int SIGNATURE = 0x4253584E; // NXSB;

    public CMSSignedData signedData;

    public void read(SeekableByteChannel channel) throws IOException {
        int size = (int) (channel.size() - channel.position());

        if (size == 0) {
            return;
        }

        ByteBuffer buffer = ByteBuffer.allocate(size).order(LITTLE_ENDIAN);
        channel.read(buffer);
        buffer.flip();

        int signature = buffer.getInt(0);
        if (signature != SIGNATURE) {
            throw new IOException("Invalid NAVX signature block");
        }

        byte[] signatureBytes = new byte[size - 8];
        buffer.position(4);
        buffer.get(signatureBytes);
        try (ASN1InputStream in = new ASN1InputStream(signatureBytes)) {
            signedData = new CMSSignedData((CMSProcessable) null, ContentInfo.getInstance(in.readObject()));
        } catch (CMSException | StackOverflowError e) {
            throw new IOException("Invalid CMS signature", e);
        }
    }

    public void write(SeekableByteChannel channel) throws IOException {
        long offset = channel.position();
        byte[] content = signedData != null ? signedData.toASN1Structure().getEncoded("DER") : new byte[0];
        if (content.length > 0) {
            ByteBuffer buffer = ByteBuffer.allocate(content.length + 12).order(LITTLE_ENDIAN);
            buffer.putInt(SIGNATURE);
            buffer.put(content);
            buffer.putInt((int) offset);
            buffer.putInt(SIGNATURE);
            buffer.flip();

            channel.write(buffer);
        }
    }
}
