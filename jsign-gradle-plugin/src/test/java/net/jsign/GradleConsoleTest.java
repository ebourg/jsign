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

package net.jsign;

import org.gradle.api.logging.LogLevel;
import org.gradle.api.logging.Logger;
import org.junit.Test;

import static org.mockito.Mockito.*;

public class GradleConsoleTest {
    
    @Test
    public void testConsole() {
        Logger logger = mock(Logger.class);
        GradleConsole console = new GradleConsole(logger);
        
        console.debug("debug");
        console.info("info");
        console.warn("warning");
        
        verify(logger).debug(eq("debug"));
        verify(logger).info(eq("info"));
        verify(logger).log(eq(LogLevel.WARN), eq("warning"), (Throwable) isNull());
    }
}
