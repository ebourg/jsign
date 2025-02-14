/*
 * Copyright 2022 Emmanuel Bourg
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

package net.jsign;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.StandardCharsets;

import org.apache.commons.compress.utils.SeekableInMemoryByteChannel;
import org.junit.Test;

import static org.junit.Assert.*;

public class ChannelUtilsTest {

    @Test
    public void testReadNullTerminatedString() throws Exception {
        String s = "ABCD\u0000";
        SeekableByteChannel channel = new SeekableInMemoryByteChannel((s).getBytes(StandardCharsets.UTF_8));

        assertEquals(s, new String(ChannelUtils.readNullTerminatedString(channel)));
    }

    @Test
    public void testReadNullTerminatedStringInvalid() {
        String s = "ABCD";
        SeekableByteChannel channel = new SeekableInMemoryByteChannel((s).getBytes(StandardCharsets.UTF_8));
        assertThrows(IOException.class, () -> ChannelUtils.readNullTerminatedString(channel));
    }

    @Test
    public void testDeleteAfterEOF() {
        byte[] data = new byte[1024];
        SeekableByteChannel channel = new SeekableInMemoryByteChannel(data);
        assertThrows(IOException.class, () -> ChannelUtils.delete(channel, 2048, 512));
    }

    @Test
    public void testDeleteAcrossEOF() {
        byte[] data = new byte[1024];
        SeekableByteChannel channel = new SeekableInMemoryByteChannel(data);
        assertThrows(IOException.class, () -> ChannelUtils.delete(channel, 1024 - 256, 512));
    }

    @Test
    public void testDeleteToEOFWithOneChunk() throws Exception {
        byte[] data = new byte[1024];
        SeekableByteChannel channel = new SeekableInMemoryByteChannel(data);
        ChannelUtils.delete(channel, 512, 512);
        
        assertEquals("channel size", 512, channel.size());
    }

    @Test
    public void testDeleteToEOFWithMultipleChunks() throws Exception {
        byte[] data = new byte[1024];
        SeekableByteChannel channel = new SeekableInMemoryByteChannel(data);
        ChannelUtils.delete(channel, 512, 512, 67);

        assertEquals("channel size", 512, channel.size());
    }

    @Test
    public void testDeleteBeforeEOFWithOneChunk() throws Exception {
        byte[] data = new byte[1024];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) (i % 64);
        }
        SeekableByteChannel channel = new SeekableInMemoryByteChannel(data);
        ChannelUtils.delete(channel, 128, 509);

        assertEquals("channel size", 1024 - 509, channel.size());
        
        channel.position(127);
        ByteBuffer buffer = ByteBuffer.allocate(2);
        channel.read(buffer);
        buffer.flip();
        
        assertEquals("value before deletion point", 63, buffer.get());
        assertEquals("value after deletion point",  61, buffer.get());
    }

    @Test
    public void testDeleteBeforeEOFWithMultipleChunks() throws Exception {
        byte[] data = new byte[1024];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) (i % 64);
        }
        SeekableByteChannel channel = new SeekableInMemoryByteChannel(data);
        ChannelUtils.delete(channel, 128, 509, 67);

        assertEquals("channel size", 1024 - 509, channel.size());

        channel.position(127);
        ByteBuffer buffer = ByteBuffer.allocate(2);
        channel.read(buffer);
        buffer.flip();

        assertEquals("value before deletion point", 63, buffer.get());
        assertEquals("value after deletion point",  61, buffer.get());
    }
}
