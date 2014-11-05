/**
 * Copyright 2014 Emmanuel Bourg
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

import junit.framework.TestCase;

public class DigestAlgorithmTest extends TestCase {
    
    public void testValueOf() {
        assertEquals(DigestAlgorithm.SHA1, DigestAlgorithm.of("SHA-1"));
        assertEquals(DigestAlgorithm.SHA1, DigestAlgorithm.of("SHA1"));
        assertEquals(DigestAlgorithm.SHA1, DigestAlgorithm.of("sha-1"));
        assertEquals(DigestAlgorithm.SHA1, DigestAlgorithm.of("sha1"));
        
        assertEquals(DigestAlgorithm.SHA256, DigestAlgorithm.of("SHA-256"));
        assertEquals(DigestAlgorithm.SHA256, DigestAlgorithm.of("SHA256"));
        assertEquals(DigestAlgorithm.SHA256, DigestAlgorithm.of("sha-256"));
        assertEquals(DigestAlgorithm.SHA256, DigestAlgorithm.of("sha256"));
        assertEquals(DigestAlgorithm.SHA256, DigestAlgorithm.of("SHA-2"));
        
        assertNull(DigestAlgorithm.of(null));
        assertNull(DigestAlgorithm.of("foo"));
    }
}
