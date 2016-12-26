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

package net.jsign.timestamp;

/**
 * Enumeration of the timestamping modes.
 * 
 * @author Emmanuel Bourg
 * @since 1.3
 */
public enum TimestampingMode {
    AUTHENTICODE,
    RFC3161;

    public static TimestampingMode of(String s) {
        for (TimestampingMode mode : values()) {
            if (mode.name().equalsIgnoreCase(s)) {
                return mode;
            }
        }
        
        if ("tsp".equalsIgnoreCase(s)) {
            return RFC3161;
        }
        
        throw new IllegalArgumentException("Unknown timestamping mode: " + s);
    }
}
