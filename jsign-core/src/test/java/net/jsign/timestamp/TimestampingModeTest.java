/**
 * Copyright 2016 Emmanuel Bourg
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

package net.jsign.timestamp;

import org.junit.Test;

import static org.junit.Assert.*;

public class TimestampingModeTest {

    @Test
    public void testOf() {
        assertEquals(TimestampingMode.AUTHENTICODE, TimestampingMode.of("AUTHENTICODE"));
        assertEquals(TimestampingMode.AUTHENTICODE, TimestampingMode.of("authenticode"));
        assertEquals(TimestampingMode.AUTHENTICODE, TimestampingMode.of("AuThEnTiCoDe"));
        
        assertEquals(TimestampingMode.RFC3161, TimestampingMode.of("RFC3161"));
        assertEquals(TimestampingMode.RFC3161, TimestampingMode.of("rfc3161"));
        assertEquals(TimestampingMode.RFC3161, TimestampingMode.of("tsp"));

        try {
            TimestampingMode.of(null);
            fail("IllegalArgumentException not thrown on null value");
        } catch (IllegalArgumentException e) {
            // expected
        }
        
        try {
            TimestampingMode.of("foo");
            fail("IllegalArgumentException not thrown on invalid value");
        } catch (IllegalArgumentException e) {
            // expected
        }
    }
}
