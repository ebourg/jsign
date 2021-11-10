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

package net.jsign.pe;

import java.util.zip.Checksum;

/**
 * Compute the checksum of a portable executable similarly to the checksum
 * function implemented into IMAGHELP.DLL. The checksum can only be updated
 * with buffers with a size that is a multiple of 4.
 * 
 * @see <a href="https://docs.microsoft.com/en-us/windows/win32/debug/imagehlp-functions">ImageHlp Functions</a>
 * @see <a href="http://www.codeproject.com/KB/cpp/PEChecksum.aspx">An Analysis of the Windows PE Checksum Algorithm</a>
 * 
 * @author Emmanuel Bourg
 * @version $Revision$, $Date$
 */
class PEImageChecksum implements Checksum {

    private static final long MAX_UNSIGNED_INT = 0x100000000L;

    /** The checksum being computed */
    private long checksum;

    /** The absolute position in the stream */
    private long position;

    /** The position of the checksum field in the stream that must be skipped */
    private final long checksumOffset;

    /** Tells if the checksum has already been skipped */
    private boolean checksumOffsetSkipped;

    public PEImageChecksum(long checksumOffset) {
        this.checksumOffset = checksumOffset;
    }

    public void update(int b) {
        throw new UnsupportedOperationException("Checksum can only be updated with buffers");
    }

    public void update(byte[] buffer, int offset, int length) {
        long checksum = this.checksum;
        
        for (int i = offset; i < offset + length; i += 4) {
            if (!checksumOffsetSkipped && position + i == checksumOffset) {
                // skip the checksum field
                checksumOffsetSkipped = true;
            } else {
                long dword = (buffer[i] & 0xFF) +
                        ((buffer[i + 1] & 0xFF) << 8) +
                        ((buffer[i + 2] & 0xFF) << 16) +
                        ((buffer[i + 3] & 0xFFL) << 24);
                
                checksum += dword;
                
                if (checksum > MAX_UNSIGNED_INT) {
                    // fold into 32 bits
                    checksum = (checksum & 0xFFFFFFFFL) + (checksum >> 32);
                }
            }
        }
        
        this.checksum = checksum;
        
        position += length - offset;
    }

    public long getValue() {
        long checksum = this.checksum;
        
        // fold twice into 16 bits
        checksum = (checksum >> 16) + (checksum & 0xFFFF);
        checksum = (checksum >> 16) + checksum;
                
        // keep the lower 16 bits and add the file length
        return (checksum & 0xFFFF) + position;
    }

    public void reset() {
        checksum = 0;
        position = 0;
        checksumOffsetSkipped = false;
    }
}
