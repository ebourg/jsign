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

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.*;

public class StdOutConsoleTest {

    private static final String LF = System.lineSeparator();

    private PrintStream stdout;
    private PrintStream stderr;

    @Before
    public void setUp() {
        stdout = System.out;
        stderr = System.err;
    }

    @Test
    public void testConsoleLevelWarn() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        System.setOut(new PrintStream(out));

        ByteArrayOutputStream err = new ByteArrayOutputStream();
        System.setErr(new PrintStream(err));

        StdOutConsole console = new StdOutConsole(0);
        console.debug("debug");
        console.info("info");
        console.warn("warning");
        
        assertEquals("", out.toString());
        assertEquals("warning" + LF, err.toString());
    }

    @Test
    public void testConsoleLevelInfo() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        System.setOut(new PrintStream(out));

        ByteArrayOutputStream err = new ByteArrayOutputStream();
        System.setErr(new PrintStream(err));

        StdOutConsole console = new StdOutConsole(1);
        console.debug("debug");
        console.info("info");
        console.warn("warning");

        assertEquals("info" + LF, out.toString());
        assertEquals("warning" + LF, err.toString());
    }

    @Test
    public void testConsoleLevelDebug() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        System.setOut(new PrintStream(out));

        ByteArrayOutputStream err = new ByteArrayOutputStream();
        System.setErr(new PrintStream(err));

        StdOutConsole console = new StdOutConsole(2);
        console.debug("debug");
        console.info("info");
        console.warn("warning");

        assertEquals("debug" + LF + "info" + LF, out.toString());
        assertEquals("warning" + LF, err.toString());
    }

    @Test
    public void testConsoleException() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        System.setOut(new PrintStream(out));

        ByteArrayOutputStream err = new ByteArrayOutputStream();
        System.setErr(new PrintStream(err));

        StdOutConsole console = new StdOutConsole(0);
        console.warn("warning", new Exception("message"));

        assertTrue(err.toString().contains("warning" + LF + "java.lang.Exception: message"));
    }

    @After
    public void tearDown() {
        System.setOut(stdout);
        System.setErr(stderr);
    }
}
