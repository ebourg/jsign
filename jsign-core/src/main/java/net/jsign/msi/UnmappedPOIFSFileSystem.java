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

import org.apache.poi.poifs.filesystem.POIFSFileSystem;

/**
 * POI file system modifying the file in place without mapping it in memory.
 *
 * @since 8.0
 */
class UnmappedPOIFSFileSystem extends POIFSFileSystem {

    private final UnmappedFileDataSource dataSource;

    UnmappedPOIFSFileSystem(File file) throws IOException {
        super(file, true);

        _data.close();
        dataSource = new UnmappedFileDataSource(file);
        _data = dataSource;
    }

    @Override
    public void writeFilesystem() throws IOException {
        super.writeFilesystem();

        dataSource.flush();
    }
}
