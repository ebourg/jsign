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
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

import static net.jsign.SignerHelper.*;

/**
 * Command line interface for signing files.
 *
 * @author Emmanuel Bourg
 * @since 1.1
 */
public class JsignCLI {

    public static void main(String... args) {
        try {
            new JsignCLI().execute(args);
        } catch (SignerException | ParseException e) {
            System.err.println("jsign: " + e.getMessage());
            if (e.getCause() != null) {
                e.getCause().printStackTrace(System.err);
            }
            System.err.println("Try `" + getProgramName() + " --help' for more information.");
            System.exit(1);
        }
    }

    private final Options options;

    JsignCLI() {
        options = new Options();
        options.addOption(Option.builder("s").hasArg().longOpt(PARAM_KEYSTORE).argName("FILE").desc("The keystore file, the SunPKCS11 configuration file or the cloud keystore name").type(File.class).build());
        options.addOption(Option.builder().hasArg().longOpt(PARAM_STOREPASS).argName("PASSWORD").desc("The password to open the keystore").build());
        options.addOption(Option.builder().hasArg().longOpt(PARAM_STORETYPE).argName("TYPE").desc("The type of the keystore:\n- JKS: Java keystore (.jks files)\n- JCEKS: SunJCE keystore (.jks files)\n- PKCS12: Standard PKCS#12 keystore (.p12 or .pfx files)\n- PKCS11: PKCS#11 hardware token\n- YUBIKEY: YubiKey security key\n- AZUREKEYVAULT: Azure Key Vault key management system\n- DIGICERTONE: DigiCert ONE Secure Software Manager\n- ESIGNER: SSL.com eSigner\n- GOOGLECLOUD: Google Cloud KMS\n").build());
        options.addOption(Option.builder("a").hasArg().longOpt(PARAM_ALIAS).argName("NAME").desc("The alias of the certificate used for signing in the keystore.").build());
        options.addOption(Option.builder().hasArg().longOpt(PARAM_KEYPASS).argName("PASSWORD").desc("The password of the private key. When using a keystore, this parameter can be omitted if the keystore shares the same password.").build());
        options.addOption(Option.builder().hasArg().longOpt(PARAM_KEYFILE).argName("FILE").desc("The file containing the private key. PEM and PVK files are supported. ").type(File.class).build());
        options.addOption(Option.builder("c").hasArg().longOpt(PARAM_CERTFILE).argName("FILE").desc("The file containing the PKCS#7 certificate chain\n(.p7b or .spc files).").type(File.class).build());
        options.addOption(Option.builder("d").hasArg().longOpt(PARAM_ALG).argName("ALGORITHM").desc("The digest algorithm (SHA-1, SHA-256, SHA-384 or SHA-512)").build());
        options.addOption(Option.builder("t").hasArg().longOpt(PARAM_TSAURL).argName("URL").desc("The URL of the timestamping authority.").build());
        options.addOption(Option.builder("m").hasArg().longOpt(PARAM_TSMODE).argName("MODE").desc("The timestamping mode (RFC3161 or Authenticode)").build());
        options.addOption(Option.builder("r").hasArg().longOpt(PARAM_TSRETRIES).argName("NUMBER").desc("The number of retries for timestamping").build());
        options.addOption(Option.builder("w").hasArg().longOpt(PARAM_TSRETRY_WAIT).argName("SECONDS").desc("The number of seconds to wait between timestamping retries").build());
        options.addOption(Option.builder("n").hasArg().longOpt(PARAM_NAME).argName("NAME").desc("The name of the application").build());
        options.addOption(Option.builder("u").hasArg().longOpt(PARAM_URL).argName("URL").desc("The URL of the application").build());
        options.addOption(Option.builder().hasArg().longOpt(PARAM_PROXY_URL).argName("URL").desc("The URL of the HTTP proxy").build());
        options.addOption(Option.builder().hasArg().longOpt(PARAM_PROXY_USER).argName("NAME").desc("The user for the HTTP proxy. If an user is needed.").build());
        options.addOption(Option.builder().hasArg().longOpt(PARAM_PROXY_PASS).argName("PASSWORD").desc("The password for the HTTP proxy user. If an user is needed.").build());
        options.addOption(Option.builder().longOpt(PARAM_REPLACE).desc("Tells if previous signatures should be replaced.").build());
        options.addOption(Option.builder("e").hasArg().longOpt(PARAM_ENCODING).argName("ENCODING").desc("The encoding of the script to be signed (UTF-8 by default, or the encoding specified by the byte order mark if there is one).").build());
        options.addOption(Option.builder().longOpt(PARAM_DETACHED).desc("Tells if a detached signature should be generated or reused.").build());
        options.addOption(Option.builder("h").longOpt("help").desc("Print the help").build());
    }

    void execute(String... args) throws SignerException, ParseException {
        DefaultParser parser = new DefaultParser();
        
        CommandLine cmd = parser.parse(options, args);

        if (cmd.hasOption("help") || args.length == 0) {
            printHelp();
            return;
        }
        
        SignerHelper helper = new SignerHelper(new StdOutConsole(1), "option");
        
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
        helper.replace(cmd.hasOption(PARAM_REPLACE));
        setOption(PARAM_ENCODING, helper, cmd);
        helper.detached(cmd.hasOption(PARAM_DETACHED));

        if (cmd.getArgList().isEmpty()) {
            throw new SignerException("No file specified");
        }

        for (String filename : cmd.getArgList()) {
            helper.sign(new File(filename));
        }
    }

    private void setOption(String key, SignerHelper helper, CommandLine cmd) {
        String value = cmd.getOptionValue(key);
        helper.param(key, value);
    }

    private void printHelp() {
        String header = "Sign and timestamp Windows executable files, Microsoft Installers (MSI), Cabinet files (CAB) or scripts (PowerShell, VBScript, JScript, WSF).\n\n";
        String footer ="\n" +
                "Examples:\n\n" +
                "   Signing with a PKCS#12 keystore and timestamping:\n\n" +
                "     jsign --keystore keystore.p12 --alias test --storepass pwd \\\n" +
                "           --tsaurl http://timestamp.sectigo.com application.exe\n\n" +
                "   Signing with a SPC certificate and a PVK key:\n\n" +
                "     jsign --certfile certificate.spc --keyfile key.pvk --keypass pwd installer.msi\n\n" +
                "Please report suggestions and issues on the GitHub project at https://github.com/ebourg/jsign/issues";

        HelpFormatter formatter = new HelpFormatter();
        formatter.setOptionComparator(null);
        formatter.setWidth(85);
        formatter.setDescPadding(1);
        formatter.printHelp(getProgramName() + " [OPTIONS] [FILE]...", header, options, footer);
    }

    private static String getProgramName() {
        return System.getProperty("basename", "java -jar jsign.jar");
    }
}
