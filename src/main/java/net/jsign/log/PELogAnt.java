/**
 * Copyright 2016
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

package net.jsign.log;

import org.apache.tools.ant.Project;
import org.apache.tools.ant.Task;

public class PELogAnt implements PELog {

    private Task task;

    public PELogAnt(Task task) {
        this.task = task;
    }

    public void info(String msg) {
        task.log(msg);
    }

    public void error(String msg, Throwable t) {
        task.log(msg, t, Project.MSG_ERR);
    }
}
