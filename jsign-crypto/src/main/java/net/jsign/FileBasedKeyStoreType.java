/*
 * Copyright 2024 Emmanuel Bourg
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

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;

abstract class FileBasedKeyStoreType extends AbstractKeyStoreType {

    @Override
    public void validate(KeyStoreBuilder params) {
        if (params.keystore() == null) {
            throw new IllegalArgumentException("keystore " + params.parameterName() + " must be set");
        }
        if (!params.createFile(params.keystore()).exists()) {
            throw new IllegalArgumentException("The keystore " + params.keystore() + " couldn't be found");
        }
        if (params.keypass() == null && params.storepass() != null) {
            // reuse the storepass as the keypass
            params.keypass(params.storepass());
        }
    }

    boolean hasSignature(File file, long signature, long mask) {
        if (file.exists()) {
            try (FileInputStream in = new FileInputStream(file)) {
                byte[] header = new byte[4];
                in.read(header);
                ByteBuffer buffer = ByteBuffer.wrap(header);
                if ((buffer.getInt(0) & mask) == signature) {
                    return true;
                }
            } catch (IOException e) {
                throw new RuntimeException("Unable to load the keystore " + file, e);
            }
        }

        return false;
    }

    /**
     * Tells if the specified file is a keystore of this type.
     *
     * @param file the path to the keystore
     */
    abstract boolean isSupported(File file);
}
