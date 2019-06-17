/**
 * Copyright 2012 Emmanuel Bourg
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

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.OptionBuilder;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

import static net.jsign.PESignerHelper.*;

/**
 * Command line interface for signing PE files.
 *
 * @author Emmanuel Bourg
 * @since 1.1
 */
public class PESignerCLI {

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

    private Options options;

    PESignerCLI() {
        options = new Options();
        options.addOption(OptionBuilder.hasArg().withLongOpt(PARAM_KEYSTORE).withArgName("FILE").withDescription("The keystore file, or the SunPKCS11 configuration file").withType(File.class).create('s'));
        options.addOption(OptionBuilder.hasArg().withLongOpt(PARAM_STOREPASS).withArgName("PASSWORD").withDescription("The password to open the keystore").create());
        options.addOption(OptionBuilder.hasArg().withLongOpt(PARAM_STORETYPE).withArgName("TYPE").withDescription("The type of the keystore:\n- JKS: Java keystore (.jks files)\n- PKCS12: Standard PKCS#12 keystore (.p12 or .pfx files)\n- PKCS11: PKCS#11 hardware token\n- GOOGLE_HSM: Google Cloud HSM Signing\n").create());
        options.addOption(OptionBuilder.hasArg().withLongOpt(PARAM_ALIAS).withArgName("NAME").withDescription("The alias of the certificate used for signing in the keystore.").create('a'));
        options.addOption(OptionBuilder.hasArg().withLongOpt(PARAM_KEYPASS).withArgName("PASSWORD").withDescription("The password of the private key. When using a keystore, this parameter can be omitted if the keystore shares the same password.").create());
        options.addOption(OptionBuilder.hasArg().withLongOpt(PARAM_KEYFILE).withArgName("FILE").withDescription("The file containing the private key. PEM and PVK files are supported. ").withType(File.class).create());
        options.addOption(OptionBuilder.hasArg().withLongOpt(PARAM_CERTFILE).withArgName("FILE").withDescription("The file containing the PKCS#7 certificate chain\n(.p7b or .spc files).").withType(File.class).create('c'));
        options.addOption(OptionBuilder.hasArg().withLongOpt(PARAM_ALG).withArgName("ALGORITHM").withDescription("The digest algorithm (SHA-1, SHA-256, SHA-384 or SHA-512)").create('d'));
        options.addOption(OptionBuilder.hasArg().withLongOpt(PARAM_TSAURL).withArgName("URL").withDescription("The URL of the timestamping authority.").create('t'));
        options.addOption(OptionBuilder.hasArg().withLongOpt(PARAM_TSMODE).withArgName("MODE").withDescription("The timestamping mode (RFC3161 or Authenticode)").create('m'));
        options.addOption(OptionBuilder.hasArg().withLongOpt(PARAM_TSRETRIES).withArgName("NUMBER").withDescription("The number of retries for timestamping").create('r'));
        options.addOption(OptionBuilder.hasArg().withLongOpt(PARAM_TSRETRY_WAIT).withArgName("SECONDS").withDescription("The number of seconds to wait between timestamping retries").create('w'));
        options.addOption(OptionBuilder.hasArg().withLongOpt(PARAM_NAME).withArgName("NAME").withDescription("The name of the application").create('n'));
        options.addOption(OptionBuilder.hasArg().withLongOpt(PARAM_URL).withArgName("URL").withDescription("The URL of the application").create('u'));
        options.addOption(OptionBuilder.hasArg().withLongOpt(PARAM_PROXY_URL).withArgName("URL").withDescription("The URL of the HTTP proxy").create());
        options.addOption(OptionBuilder.hasArg().withLongOpt(PARAM_PROXY_USER).withArgName("NAME").withDescription("The user for the HTTP proxy. If an user is needed.").create());
        options.addOption(OptionBuilder.hasArg().withLongOpt(PARAM_PROXY_PASS).withArgName("PASSWORD").withDescription("The password for the HTTP proxy user. If an user is needed.").create());
        options.addOption(OptionBuilder.hasArg().withLongOpt(PARAM_GOOGLE_CLOUD_HSM_KEY_ID).withArgName("GOOGLE_CLOUD_HSM_KEY_ID").withDescription("The key id of the key to sign with from Google Cloud HSM. If this is set it will sign using HSM logic.").create());
        options.addOption(OptionBuilder.withLongOpt(PARAM_REPLACE).withDescription("Tells if previous signatures should be replaced.").create());
        options.addOption(OptionBuilder.withLongOpt("help").withDescription("Print the help").create('h'));
    }

    void execute(String... args) throws SignerException, ParseException {
        DefaultParser parser = new DefaultParser();
        
        CommandLine cmd = parser.parse(options, args);

        if (cmd.hasOption("help") || args.length == 0) {
            printHelp();
            return;
        }
        
        PESignerHelper helper = new PESignerHelper(new StdOutConsole(), "option");
        
        setOption(PARAM_KEYSTORE, helper, cmd);
        setOption(PARAM_STOREPASS, helper, cmd);
        setOption(PARAM_STORETYPE, helper, cmd);
        setOption(PARAM_ALIAS, helper, cmd);
        setOption(PARAM_KEYPASS, helper, cmd);
        setOption(PARAM_KEYFILE, helper, cmd);
        setOption(PARAM_CERTFILE, helper, cmd);
        setOption(PARAM_ALG, helper, cmd);
        setOption(PARAM_TSAURL, helper, cmd);
        setOption(PARAM_TSMODE, helper, cmd);
        setOption(PARAM_TSRETRIES, helper, cmd);
        setOption(PARAM_TSRETRY_WAIT, helper, cmd);
        setOption(PARAM_NAME, helper, cmd);
        setOption(PARAM_URL, helper, cmd);
        setOption(PARAM_PROXY_URL, helper, cmd);
        setOption(PARAM_PROXY_USER, helper, cmd);
        setOption(PARAM_PROXY_PASS, helper, cmd);
        setOption(PARAM_GOOGLE_CLOUD_HSM_KEY_ID, helper, cmd);
        helper.replace(cmd.hasOption("replace"));

        File file = cmd.getArgList().isEmpty() ? null : new File(cmd.getArgList().get(0));

        helper.sign(file);
    }

    private void setOption(String key, PESignerHelper helper, CommandLine cmd) throws SignerException {
        String value = cmd.getOptionValue(key);
        helper.param(key, value);
    }

    private void printHelp() {
        String header = "Sign and timestamp a Windows executable file.\n\n";
        String footer = "\nPlease report suggestions and issues on the GitHub project at https://github.com/ebourg/jsign/issues";

        HelpFormatter formatter = new HelpFormatter();
        formatter.setOptionComparator(null);
        formatter.setWidth(85);
        formatter.setDescPadding(1);
        formatter.printHelp("java -jar jsign.jar [OPTIONS] FILE", header, options, footer);
    }
}
