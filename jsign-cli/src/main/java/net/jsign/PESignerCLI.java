/*
 * Copyright 2012 Emmanuel Bourg
 * Copyright 2019 Björn Kautler
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

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.OptionBuilder;
import org.apache.commons.cli.ParseException;

import java.io.File;

import static net.jsign.PESignerHelper.PARAM_REPLACE;

/**
 * Command line interface for signing PE files.
 *
 * @author Emmanuel Bourg
 * @since 1.1
 */
public class PESignerCLI extends BaseSignerCLI<PESignerHelper> {

    public static void main(String... args) {
        try {
            new PESignerCLI().execute(args);
        } catch (SignerException | ParseException e) {
            System.err.println("pesign: " + e.getMessage());
            if (e.getCause() != null) {
                e.getCause().printStackTrace(System.err);
            }
            System.err.println("Try `pesign --help' for more information.");
            System.exit(1);
        }
    }

    PESignerCLI() {
        options.addOption(OptionBuilder.withLongOpt(PARAM_REPLACE).withDescription("Tells if previous signatures should be replaced.").create());
    }

    @Override
    PESignerHelper createSignerHelper(Console console, String parameterName) {
        return new PESignerHelper(console, parameterName);
    }

    @Override
    void doExecute(PESignerHelper helper, CommandLine cmd, File file) throws SignerException {
        helper.replace(cmd.hasOption("replace"));
        helper.sign(file);
    }
}
