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

import java.io.File;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.List;

import org.junit.Test;

import static org.junit.Assert.*;

public class DirectoryScannerTest {

    @Test
    public void testGlobToRegExp() {
        DirectoryScanner scanner = new DirectoryScanner();
        assertEquals("RegExp for pattern *.exe", "\\Q\\E[^/]*\\Q.exe\\E", scanner.globToRegExp("*.exe"));
        assertEquals("RegExp for pattern build/*.exe", "\\Qbuild\\E/\\Q\\E[^/]*\\Q.exe\\E", scanner.globToRegExp("build/*.exe"));
        assertEquals("RegExp for pattern build/*.exe", "\\Qbuild\\E/\\Q\\E[^/]*\\Qapp\\E[^/]*\\Q.exe\\E", scanner.globToRegExp("build/*app*.exe"));
        assertEquals("RegExp for pattern build//*.exe", "\\Qbuild\\E/\\Q\\E[^/]*\\Q.exe\\E", scanner.globToRegExp("build//*.exe"));
        assertEquals("RegExp for pattern build\\*.exe", "\\Qbuild\\E/\\Q\\E[^/]*\\Q.exe\\E", scanner.globToRegExp("build\\*.exe"));
        assertEquals("RegExp for pattern build/**/package.msix", "\\Qbuild\\E/(?:|.*/)\\Qpackage.msix\\E", scanner.globToRegExp("build/**/package.msix"));
        assertEquals("RegExp for pattern build/**/artifacts/*.dll", "\\Qbuild\\E/(?:|.*/)\\Q\\E[^/]*\\Q.dll\\E", scanner.globToRegExp("build/**/*.dll"));
    }

    @Test
    public void testFindBaseDirectory() {
        DirectoryScanner scanner = new DirectoryScanner();
        assertEquals("Base directory for pattern ''", "", scanner.findBaseDirectory(""));
        assertEquals("Base directory for pattern *.exe", "", scanner.findBaseDirectory("*.exe"));
        assertEquals("Base directory for pattern **/*.exe", "", scanner.findBaseDirectory("**/*.exe"));
        assertEquals("Base directory for pattern /build/", "/build/", scanner.findBaseDirectory("/build/"));
        assertEquals("Base directory for pattern build/*.exe", "build/", scanner.findBaseDirectory("build/*.exe"));
        assertEquals("Base directory for pattern build/foo/**/bar/*.exe", "build/foo/", scanner.findBaseDirectory("build/foo/**/bar/*.exe"));
        assertEquals("Base directory for pattern ../../foo/bar*/*.dll", "../../foo/", scanner.findBaseDirectory("../../foo/bar*/*.dll"));
        assertEquals("Base directory for pattern ../../*foo*/bar*/*.dll", "../../", scanner.findBaseDirectory("../../*foo*/bar*/*.dll"));
        assertEquals("Base directory for pattern c:/dev/jsign/*.xml", "c:/dev/jsign/", scanner.findBaseDirectory("c:/dev/jsign/*.xml"));
    }

    @Test
    public void testMaxPatternDepth() {
        DirectoryScanner scanner = new DirectoryScanner();
        assertEquals("Max depth for pattern ''", 0, scanner.maxPatternDepth(""));
        assertEquals("Max depth for pattern *.exe", 0, scanner.maxPatternDepth("*.exe"));
        assertEquals("Max depth for pattern **/*.exe", 50, scanner.maxPatternDepth("**/*.exe"));
        assertEquals("Max depth for pattern build/*.exe", 1, scanner.maxPatternDepth("build/*.exe"));
        assertEquals("Max depth for pattern build/foo/**/bar/*.exe", 50, scanner.maxPatternDepth("build/foo/**/bar/*.exe"));
        assertEquals("Max depth for pattern foo/bar*/*.dll", 2, scanner.maxPatternDepth("foo/bar*/*.dll"));
        assertEquals("Max depth for pattern *foo*/bar*/*.dll", 2, scanner.maxPatternDepth("*foo*/bar*/*.dll"));
    }

    @Test
    public void testScanCurrentDirectory() throws Exception {
        DirectoryScanner scanner = new DirectoryScanner();
        List<Path> matches = scanner.scan("pom.xml");

        assertEquals("number of matches", 1, matches.size());
        assertEquals("match", new File("pom.xml"), matches.get(0).toFile());
    }

    @Test
    public void testScanParentDirectory() throws Exception {
        DirectoryScanner scanner = new DirectoryScanner();
        List<Path> matches = scanner.scan("..\\pom.xml");

        assertEquals("number of matches", 1, matches.size());
        assertEquals("match", new File("../pom.xml"), matches.get(0).toFile());
    }

    @Test
    public void testScanSubDirectory() throws Exception {
        DirectoryScanner scanner = new DirectoryScanner();
        List<Path> matches = scanner.scan("target/pom.xml");

        assertEquals("number of matches", 0, matches.size());
    }

    @Test
    public void testScanCurrentDirectoryWildcard() throws Exception {
        DirectoryScanner scanner = new DirectoryScanner();
        List<Path> matches = scanner.scan("*.xml");

        assertEquals("number of matches", 1, matches.size());
        assertEquals("match", new File("pom.xml"), matches.get(0).toFile());
    }

    @Test
    public void testScanParentDirectoryWildcard() throws Exception {
        DirectoryScanner scanner = new DirectoryScanner();
        List<Path> matches = scanner.scan("..\\*.xml");

        assertEquals("number of matches", 1, matches.size());
        assertEquals("match", new File("../pom.xml"), matches.get(0).toFile());
    }

    @Test
    public void testScanAbsoluteDirectoryWildcard() throws Exception {
        DirectoryScanner scanner = new DirectoryScanner();
        List<Path> matches = scanner.scan(new File("").getAbsolutePath() + "/*.xml");

        assertEquals("number of matches", 1, matches.size());
        assertEquals("match", new File(new File("").getAbsolutePath(), "pom.xml"), matches.get(0).toFile());
    }

    @Test
    public void testScanCurrentDirectoryRecursively() throws Exception {
        DirectoryScanner scanner = new DirectoryScanner();
        List<Path> matches = scanner.scan("**/pom.xml");

        assertEquals("number of matches", 1, matches.size());
        assertEquals("match", new File("pom.xml"), matches.get(0).toFile());
    }

    @Test
    public void testScanParentDirectoryRecursively() throws Exception {
        DirectoryScanner scanner = new DirectoryScanner();
        List<Path> matches = scanner.scan("../jsign-c*/**/pom.xml");
        matches.sort(Comparator.comparing(Path::toString));

        assertEquals("number of matches", 3, matches.size());
        assertEquals("match", new File("../jsign-cli/pom.xml"), matches.get(0).toFile());
        assertEquals("match", new File("../jsign-core/pom.xml"), matches.get(1).toFile());
        assertEquals("match", new File("../jsign-crypto/pom.xml"), matches.get(2).toFile());
    }

    @Test
    public void testScanSubDirectoryRecursively() throws Exception {
        DirectoryScanner scanner = new DirectoryScanner();
        List<Path> matches = scanner.scan("../jsign-core/src/**/*.exe");

        assertEquals("number of matches", 1, matches.size());
        assertEquals("match", new File("../jsign-core/src/test/resources/wineyes.exe"), matches.get(0).toFile());
    }

    @Test
    public void testScanAbsoluteDirectoryRecursively() throws Exception {
        DirectoryScanner scanner = new DirectoryScanner();
        List<Path> matches = scanner.scan(new File("..").getCanonicalPath() + "/jsign-core/src/**/*.exe");

        assertEquals("number of matches", 1, matches.size());
        assertEquals("match", new File(new File("..").getCanonicalPath(), "jsign-core/src/test/resources/wineyes.exe"), matches.get(0).toFile());
    }
}
