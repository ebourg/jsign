/*
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
import java.nio.channels.ReadableByteChannel;

import static java.nio.ByteOrder.*;

/**
 * NAVX file header
 *
 *  <pre>
 *  signature                       4 bytes  (NAVX)
 *  unknown                        24 bytes
 *  content size                    4 bytes
 *  unknown                         4 bytes
 *  signature                       4 bytes  (NAVX)
 *  </pre>
 *
 * @since 6.0
 */
class NAVXHeader {

    public static final int SIGNATURE = 0x5856414E; // NAVX;
    public static final int SIZE = 40;

    public int contentSize;

    public void read(ReadableByteChannel channel) throws IOException {
        ByteBuffer buffer = ByteBuffer.allocate(SIZE).order(LITTLE_ENDIAN);
        channel.read(buffer);
        buffer.flip();

        int signature = buffer.getInt();
        if (signature != SIGNATURE) {
            throw new IOException("Invalid NAVX header signature");
        }
        contentSize = buffer.getInt(28);

        signature = buffer.getInt(36);
        if (signature != SIGNATURE) {
            throw new IOException("Invalid NAVX header signature");
        }
    }
}
