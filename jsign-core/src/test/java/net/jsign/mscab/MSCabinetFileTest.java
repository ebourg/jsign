/**
 * Copyright 2021 Emmanuel Bourg and contributors
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

import java.io.File;

import org.junit.Test;

import static org.junit.Assert.*;

public class MSCabinetFileTest {

    @Test
    public void testIsMSCabinetFile() throws Exception {
        assertTrue(MSCabinetFile.isMSCabinetFile(new File("target/test-classes/mscab/sample1.cab")));
        assertFalse(MSCabinetFile.isMSCabinetFile(new File("target/test-classes/wineyes.exe")));
        assertFalse(MSCabinetFile.isMSCabinetFile(new File("target")));
        assertFalse(MSCabinetFile.isMSCabinetFile(new File("target/non-existent")));
    }
}
