/*
 * Copyright 2026 Emmanuel Bourg
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

package net.jsign.msi;

import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import org.apache.poi.poifs.nio.FileBackedDataSource;

/**
 * POI data source modifying the file without mapping it in memory.
 *
 * @since 8.0
 */
class UnmappedFileDataSource extends FileBackedDataSource {

    /** The blocks modified by POI, by position in the file */
    private final Map<Long, ByteBuffer> blocks = new LinkedHashMap<>();

    /** The position of the blocks held */
    private final Map<ByteBuffer, Long> positions = new IdentityHashMap<>();

    UnmappedFileDataSource(File file) throws IOException {
        super(file, false);
    }

    @Override
    public ByteBuffer read(int length, long position) throws IOException {
        ByteBuffer block = blocks.get(position);

        if (block == null) {
            if (position >= size()) {
                throw new IndexOutOfBoundsException("Position " + position + " past the end of the file");
            }

            block = ByteBuffer.allocate(length);
            getChannel().read(block, position);

            blocks.put(position, block);
            positions.put(block, position);
        }

        block.position(0);
        block.limit(block.capacity());

        return block;
    }

    @Override
    public void releaseBuffer(ByteBuffer block) {
        Long position = positions.remove(block);
        if (position != null) {
            blocks.remove(position);
            try {
                writeBlock(block, position);
            } catch (IOException e) {
                throw new RuntimeException("Unable to write the block at the position " + position, e);
            }
        }
    }

    /**
     * Writes the blocks still held to the file.
     */
    void flush() throws IOException {
        for (Map.Entry<Long, ByteBuffer> entry : blocks.entrySet()) {
            writeBlock(entry.getValue(), entry.getKey());
        }

        blocks.clear();
        positions.clear();
    }

    private void writeBlock(ByteBuffer block, long position) throws IOException {
        block.position(0);
        block.limit(block.capacity());
        write(block, position);
    }
}
