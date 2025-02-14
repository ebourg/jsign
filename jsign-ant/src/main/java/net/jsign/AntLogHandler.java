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

import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;

import org.apache.tools.ant.Project;
import org.apache.tools.ant.Task;

/**
 * Console implementation for Ant tasks.
 *
 * @since 7.0
 */
class AntLogHandler extends Handler {

    private final Task task;

    public AntLogHandler(Task task) {
        this.task = task;
    }

    @Override
    public void publish(LogRecord record) {
        int level = record.getLevel().intValue();
        if (level >= Level.SEVERE.intValue()) {
            task.log(record.getMessage(), record.getThrown(), Project.MSG_ERR);
        } else if (level >= Level.WARNING.intValue()) {
            task.log(record.getMessage(), record.getThrown(), Project.MSG_WARN);
        } else if (level >= Level.INFO.intValue()) {
            task.log(record.getMessage(), record.getThrown(), Project.MSG_INFO);
        } else if (level >= Level.FINE.intValue()) {
            task.log(record.getMessage(), record.getThrown(), Project.MSG_VERBOSE);
        } else {
            task.log(record.getMessage(), record.getThrown(), Project.MSG_DEBUG);
        }
    }

    @Override
    public void flush() {
    }

    @Override
    public void close() throws SecurityException {
    }
}
