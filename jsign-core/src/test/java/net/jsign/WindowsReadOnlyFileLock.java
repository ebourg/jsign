/*
 * Copyright 2026 Emmanuel Bourg
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

import java.io.File;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;

import com.sun.jna.platform.win32.Kernel32;

import static com.sun.jna.platform.win32.WinBase.*;
import static com.sun.jna.platform.win32.WinNT.*;

/**
 * Locks a file in share read mode on Windows. Any attempt to open a read/write channel
 * on the file while locked will result in a FileSystemException.
 */
public class WindowsReadOnlyFileLock implements Lock, AutoCloseable {

    private final File file;
    private HANDLE hFile = INVALID_HANDLE_VALUE;

    public WindowsReadOnlyFileLock(File file) {
        this.file = file;
    }

    @Override
    public void lock() {
        if (!tryLock()) {
            throw new IllegalStateException("Unable to acquire lock on " + file.getAbsolutePath());
        }
    }

    @Override
    public boolean tryLock() {
        if (isLocked()) {
            return true;
        }

        HANDLE handle = Kernel32.INSTANCE.CreateFile(file.getAbsolutePath(), GENERIC_READ, FILE_SHARE_READ, null, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, null);
        if (INVALID_HANDLE_VALUE.equals(handle)) {
            return false;
        }

        this.hFile = handle;
        return true;
    }

    @Override
    public void unlock() {
        if (isLocked()) {
            Kernel32.INSTANCE.CloseHandle(hFile);
            this.hFile = INVALID_HANDLE_VALUE;
        }
    }

    @Override
    public void close() {
        unlock();
    }

    private boolean isLocked() {
        return !INVALID_HANDLE_VALUE.equals(hFile);
    }

    @Override
    public void lockInterruptibly() {
        lock();
    }

    @Override
    public boolean tryLock(long time, TimeUnit unit) {
        return tryLock();
    }

    @Override
    public Condition newCondition() {
        throw new UnsupportedOperationException();
    }
}
