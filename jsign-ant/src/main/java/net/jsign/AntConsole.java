/**
 * Copyright 2017 Emmanuel Bourg
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

/**
 * Console implementation for Ant tasks.
 * 
 * @author Emmanuel Bourg
 * @since 2.0
 */
class AntConsole implements Console {

    private final Task task;

    public AntConsole(Task task) {
        this.task = task;
    }

    public void debug(String message) {
        task.log(message, Project.MSG_DEBUG);
    }

    public void info(String message) {
        task.log(message, Project.MSG_INFO);
    }

    public void warn(String message) {
        task.log(message, Project.MSG_WARN);
    }

    public void warn(String message, Throwable t) {
        task.log(message, t, Project.MSG_WARN);
    }
}
