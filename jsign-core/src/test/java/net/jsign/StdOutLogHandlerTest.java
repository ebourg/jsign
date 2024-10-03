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

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.*;

public class StdOutLogHandlerTest {

    private static final String LF = System.lineSeparator();

    private PrintStream stdout;
    private PrintStream stderr;

    @Before
    public void setUp() {
        stdout = System.out;
        stderr = System.err;
    }

    private Logger getLogger(Level level) {
        Logger log = Logger.getAnonymousLogger();
        log.setUseParentHandlers(false);
        log.setLevel(level);
        log.addHandler(new StdOutLogHandler());
        return log;
    }

    @Test
    public void testLoggingLevelWarn() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        System.setOut(new PrintStream(out));

        ByteArrayOutputStream err = new ByteArrayOutputStream();
        System.setErr(new PrintStream(err));

        Logger log = getLogger(Level.WARNING);
        log.finest("debug");
        log.fine("verbose");
        log.info("info");
        log.warning("warning");
        
        assertEquals("", out.toString());
        assertEquals("warning" + LF, err.toString());
    }

    @Test
    public void testLoggingLevelInfo() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        System.setOut(new PrintStream(out));

        ByteArrayOutputStream err = new ByteArrayOutputStream();
        System.setErr(new PrintStream(err));

        Logger log = getLogger(Level.INFO);
        log.finest("debug");
        log.fine("verbose");
        log.info("info");
        log.warning("warning");

        assertEquals("info" + LF, out.toString());
        assertEquals("warning" + LF, err.toString());
    }

    @Test
    public void testLoggingLevelVerbose() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        System.setOut(new PrintStream(out));

        ByteArrayOutputStream err = new ByteArrayOutputStream();
        System.setErr(new PrintStream(err));

        Logger log = getLogger(Level.FINE);
        log.finest("debug");
        log.fine("verbose");
        log.info("info");
        log.warning("warning");

        assertEquals("verbose" + LF + "info" + LF, out.toString());
        assertEquals("warning" + LF, err.toString());
    }

    @Test
    public void testLoggingLevelDebug() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        System.setOut(new PrintStream(out));

        ByteArrayOutputStream err = new ByteArrayOutputStream();
        System.setErr(new PrintStream(err));

        Logger log = getLogger(Level.FINEST);
        log.finest("debug");
        log.fine("verbose");
        log.info("info");
        log.warning("warning");

        assertEquals("debug" + LF + "verbose" + LF + "info" + LF, out.toString());
        assertEquals("warning" + LF, err.toString());
    }

    @Test
    public void testLoggingException() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        System.setOut(new PrintStream(out));

        ByteArrayOutputStream err = new ByteArrayOutputStream();
        System.setErr(new PrintStream(err));

        Logger log = getLogger(Level.WARNING);
        log.log(Level.WARNING, "warning", new Exception("message"));

        assertTrue(err.toString().contains("warning" + LF + "java.lang.Exception: message"));
    }

    @After
    public void tearDown() {
        System.setOut(stdout);
        System.setErr(stderr);
    }
}
