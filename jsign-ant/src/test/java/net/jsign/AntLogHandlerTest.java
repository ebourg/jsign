/*
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

import org.apache.tools.ant.Project;
import org.apache.tools.ant.Task;
import org.junit.Test;

import static org.mockito.Mockito.*;

public class AntLogHandlerTest {

    @Test
    public void testLogging() {
        Task task = mock(Task.class);

        Logger log = Logger.getAnonymousLogger();
        log.setUseParentHandlers(false);
        log.setLevel(Level.ALL);
        log.addHandler(new AntLogHandler(task));
        log.finest("debug");
        log.fine("verbose");
        log.info("info");
        log.warning("warning");
        log.severe("severe");
        
        verify(task).log(eq("debug"), isNull(), eq(Project.MSG_DEBUG));
        verify(task).log(eq("verbose"), isNull(), eq(Project.MSG_VERBOSE));
        verify(task).log(eq("info"), isNull(), eq(Project.MSG_INFO));
        verify(task).log(eq("warning"), isNull(), eq(Project.MSG_WARN));
        verify(task).log(eq("severe"), isNull(), eq(Project.MSG_ERR));
    }
}
