/*
 * Copyright 2024 Björn Kautler
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

import org.kohsuke.MetaInfServices;

import java.io.File;

/**
 * JCE keystore
 */
@MetaInfServices(JsignKeyStore.class)
public class JceKeyStore extends FileBasedKeyStore {
    @Override
    public String getType() {
        return "JCEKS";
    }

    @Override
    boolean isSupported(File file) {
        String filename = file.getName().toLowerCase();
        return hasSignature(file, 0xCECECECEL, 0xFFFFFFFFL) || filename.endsWith(".jceks");
    }
}
