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

package net.jsign;

import java.util.logging.Level;
import java.util.logging.Logger;

import org.apache.maven.plugin.logging.Log;
import org.junit.Test;

import static org.mockito.Mockito.*;

public class MavenLogHandlerTest {

    @Test
    public void testLogging() {
        Log log = mock(Log.class);

        Logger logger = Logger.getAnonymousLogger();
        logger.setLevel(Level.ALL);
        logger.setUseParentHandlers(false);
        logger.addHandler(new MavenLogHandler(log));

        // without exception
        logger.log(Level.FINEST, "debug");
        logger.log(Level.FINE, "verbose");
        logger.log(Level.INFO, "info");
        logger.log(Level.WARNING, "warning");
        logger.log(Level.SEVERE, "error");

        // with exception
        logger.log(Level.FINEST, "debug", new Exception());
        logger.log(Level.FINE, "verbose", new Exception());
        logger.log(Level.INFO, "info", new Exception());
        logger.log(Level.WARNING, "warning", new Exception());
        logger.log(Level.SEVERE, "error", new Exception());

        verify(log).debug(eq("debug"));
        verify(log).info(eq("verbose"));
        verify(log).info(eq("info"));
        verify(log).warn(eq("warning"));
        verify(log).warn(eq("error"));

        verify(log).debug(eq("debug"), isNotNull());
        verify(log).info(eq("verbose"), isNotNull());
        verify(log).info(eq("info"), isNotNull());
        verify(log).warn(eq("warning"), isNotNull());
        verify(log).warn(eq("error"), isNotNull());
    }
}
