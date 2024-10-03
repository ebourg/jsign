/**
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

package net.jsign.spi;

import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;

import net.jsign.Signable;

/**
 * Service Provider Interface for {@link Signable} implementations
 *
 * @since 7.0
 */
public interface SignableProvider {

    /**
     * Tells if the provider supports the specified file.
     *
     * @param file the file to be signed
     * @return <tt>true</tt> if the provider supports the file, <tt>false</tt> otherwise
     * @throws IOException if an I/O error occurs
     */
    boolean isSupported(File file) throws IOException;

    /**
     * Creates a Signable instance for the specified file.
     *
     * @param file the file to be signed
     * @param encoding the character encoding (for text files only).
     * @return the signable object for the specified file
     * @throws IOException if an I/O error occurs
     */
    Signable create(File file, Charset encoding) throws IOException;
}
