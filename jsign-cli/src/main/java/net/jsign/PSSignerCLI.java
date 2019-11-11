/*
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

import static net.jsign.PSSignerHelper.PARAM_SCRIPT_ENCODING;

/**
 * Command line interface for signing PE files.
 *
 * @author Emmanuel Bourg
 * @since 1.1
 */
public class PSSignerCLI extends BaseSignerCLI<PSSignerHelper> {

    public static void main(String... args) {
        try {
            new PSSignerCLI().execute(args);
        } catch (SignerException | ParseException e) {
            System.err.println("pssign: " + e.getMessage());
            if (e.getCause() != null) {
                e.getCause().printStackTrace(System.err);
            }
            System.err.println("Try `pssign --help' for more information.");
            System.exit(1);
        }
    }

    PSSignerCLI() {
        options.addOption(OptionBuilder.hasArg().withLongOpt(PARAM_SCRIPT_ENCODING).withArgName("SCRIPT_ENCODING").withDescription("The encoding of the script to be signed (UTF-8 by default).").create('e'));
    }

    @Override
    PSSignerHelper createSignerHelper(Console console, String parameterName) {
        return new PSSignerHelper(console, parameterName);
    }

    @Override
    void doExecute(PSSignerHelper helper, CommandLine cmd, File file) throws SignerException {
        setOption(PARAM_SCRIPT_ENCODING, helper, cmd);
        helper.sign(file);
    }
}
