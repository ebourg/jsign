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

import org.apache.tools.ant.Project;
import org.apache.tools.ant.Task;
import org.junit.Test;

import static org.mockito.Mockito.*;

public class AntConsoleTest {

    @Test
    public void testConsole() {
        Task task = mock(Task.class);
        AntConsole console = new AntConsole(task);
        
        console.debug("debug");
        console.info("info");
        console.warn("warning");
        console.warn("warning", null);
        
        verify(task).log(eq("debug"), eq(Project.MSG_DEBUG));
        verify(task).log(eq("info"), eq(Project.MSG_INFO));
        verify(task).log(eq("warning"), eq(Project.MSG_WARN));
        verify(task).log(eq("warning"), (Throwable) isNull(), eq(Project.MSG_WARN));
    }
}
