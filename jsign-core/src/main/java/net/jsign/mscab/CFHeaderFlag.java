/**
 * Copyright 2019 Emmanuel Bourg
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

package net.jsign.mscab;

enum CFHeaderFlag {

    PREV_CABINET(0x0001),
    NEXT_CABINET(0x0002),
    RESERVE_PRESENT(0x0004);

    int value;

    CFHeaderFlag(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }

    public boolean checkFrom(int x) {
        return (x & value) != 0;
    }
}
