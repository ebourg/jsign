/*
 * Copyright 2017 Emmanuel Bourg and contributors
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

import net.jsign.timestamp.TimestampingMode;

/**
 * Helper class to create AuthenticodeSigner instances with untyped parameters.
 * This is used internally to share the parameter validation logic
 * between the Ant task, the Maven/Gradle plugins and the CLI tool.
 *
 * @since 2.0
 */
class SignerHelper {
    public static final String PARAM_COMMAND = "command";
    public static final String PARAM_KEYSTORE = "keystore";
    public static final String PARAM_STOREPASS = "storepass";
    public static final String PARAM_STORETYPE = "storetype";
    public static final String PARAM_ALIAS = "alias";
    public static final String PARAM_KEYPASS = "keypass";
    public static final String PARAM_KEYFILE = "keyfile";
    public static final String PARAM_CERTFILE = "certfile";
    public static final String PARAM_ALG = "alg";
    public static final String PARAM_TSAURL = "tsaurl";
    public static final String PARAM_TSMODE = "tsmode";
    public static final String PARAM_TSRETRIES = "tsretries";
    public static final String PARAM_TSRETRY_WAIT = "tsretrywait";
    public static final String PARAM_NAME = "name";
    public static final String PARAM_URL = "url";
    public static final String PARAM_PROXY_URL = "proxyUrl";
    public static final String PARAM_PROXY_USER = "proxyUser";
    public static final String PARAM_PROXY_PASS = "proxyPass";
    public static final String PARAM_NON_PROXY_HOSTS = "nonProxyHosts";
    public static final String PARAM_REPLACE = "replace";
    public static final String PARAM_LAZY = "lazy";
    public static final String PARAM_ENCODING = "encoding";
    public static final String PARAM_DETACHED = "detached";
    public static final String PARAM_FORMAT = "format";
    public static final String PARAM_VALUE = "value";
    public static final String PARAM_VERBOSE = "verbose";

    /** The name used to refer to a configuration parameter */
    private final String parameterName;

    /** The command to execute */
    private String command = "sign";

    /** The base directory to resolve the relative paths */
    private File basedir;

    private String keystore;
    private String storepass;
    private String storetype;
    private String alias;
    private String keypass;
    private String keyfile;
    private String certfile;
    private String tsaurl;
    private String tsmode;
    private int tsretries = -1;
    private int tsretrywait = -1;
    private String alg;
    private String name;
    private String url;
    private final ProxySettings proxySettings = new ProxySettings();
    private boolean replace;
    private boolean lazy;
    private String encoding;
    private boolean detached;
    private String format;
    private String value;
    private boolean verbose;

    public SignerHelper(String parameterName) {
        this.parameterName = parameterName;
    }

    SignerHelper basedir(File basedir) {
        this.basedir = basedir;
        return this;
    }

    public SignerHelper command(String command) {
        this.command = command;
        return this;
    }

    public SignerHelper keystore(String keystore) {
        this.keystore = keystore;
        return this;
    }

    public SignerHelper storepass(String storepass) {
        this.storepass = storepass;
        return this;
    }

    public SignerHelper storetype(String storetype) {
        this.storetype = storetype;
        return this;
    }

    public SignerHelper alias(String alias) {
        this.alias = alias;
        return this;
    }

    public SignerHelper keypass(String keypass) {
        this.keypass = keypass;
        return this;
    }

    public SignerHelper keyfile(String keyfile) {
        this.keyfile = keyfile;
        return this;
    }

    public SignerHelper keyfile(File keyfile) {
        this.keyfile = keyfile != null ? keyfile.getAbsolutePath() : null;
        return this;
    }

    public SignerHelper certfile(String certfile) {
        this.certfile = certfile;
        return this;
    }

    public SignerHelper certfile(File certfile) {
        this.certfile = certfile != null ? certfile.getAbsolutePath() : null;
        return this;
    }

    public SignerHelper alg(String alg) {
        this.alg = alg;
        return this;
    }

    public SignerHelper tsaurl(String tsaurl) {
        this.tsaurl = tsaurl;
        return this;
    }

    public SignerHelper tsmode(String tsmode) {
        this.tsmode = tsmode;
        return this;
    }

    public SignerHelper tsretries(int tsretries) {
        this.tsretries = tsretries;
        return this;
    }

    public SignerHelper tsretrywait(int tsretrywait) {
        this.tsretrywait = tsretrywait;
        return this;
    }

    public SignerHelper name(String name) {
        this.name = name;
        return this;
    }

    public SignerHelper url(String url) {
        this.url = url;
        return this;
    }

    public SignerHelper proxyUrl(String proxyUrl) {
        this.proxySettings.url = proxyUrl;
        return this;
    }

    public SignerHelper proxyUser(String proxyUser) {
        this.proxySettings.username = proxyUser;
        return this;
    }

    public SignerHelper proxyPass(String proxyPass) {
        this.proxySettings.password = proxyPass;
        return this;
    }

    public SignerHelper nonProxyHosts(String nonProxyHosts) {
        this.proxySettings.nonProxyHosts = nonProxyHosts;
        return this;
    }

    public SignerHelper replace(boolean replace) {
        this.replace = replace;
        return this;
    }

    public SignerHelper lazy(boolean lazy) {
        this.lazy = lazy;
        return this;
    }

    public SignerHelper encoding(String encoding) {
        this.encoding = encoding;
        return this;
    }

    public SignerHelper detached(boolean detached) {
        this.detached = detached;
        return this;
    }

    public SignerHelper format(String format) {
        this.format = format;
        return this;
    }

    public SignerHelper value(String value) {
        this.value = value;
        return this;
    }

    public SignerHelper verbose(boolean verbose) {
        this.verbose = verbose;
        return this;
    }

    public SignerHelper param(String key, String value) {
        if (value == null) {
            return this;
        }
        
        switch (key) {
            case PARAM_COMMAND:    return command(value);
            case PARAM_KEYSTORE:   return keystore(value);
            case PARAM_STOREPASS:  return storepass(value);
            case PARAM_STORETYPE:  return storetype(value);
            case PARAM_ALIAS:      return alias(value);
            case PARAM_KEYPASS:    return keypass(value);
            case PARAM_KEYFILE:    return keyfile(value);
            case PARAM_CERTFILE:   return certfile(value);
            case PARAM_ALG:        return alg(value);
            case PARAM_TSAURL:     return tsaurl(value);
            case PARAM_TSMODE:     return tsmode(value);
            case PARAM_TSRETRIES:  return tsretries(Integer.parseInt(value));
            case PARAM_TSRETRY_WAIT: return tsretrywait(Integer.parseInt(value));
            case PARAM_NAME:       return name(value);
            case PARAM_URL:        return url(value);
            case PARAM_PROXY_URL:  return proxyUrl(value);
            case PARAM_PROXY_USER: return proxyUser(value);
            case PARAM_PROXY_PASS: return proxyPass(value);
            case PARAM_NON_PROXY_HOSTS: return nonProxyHosts(value);
            case PARAM_REPLACE:    return replace("true".equalsIgnoreCase(value));
            case PARAM_LAZY:       return lazy("true".equalsIgnoreCase(value));
            case PARAM_ENCODING:   return encoding(value);
            case PARAM_DETACHED:   return detached("true".equalsIgnoreCase(value));
            case PARAM_FORMAT:     return format(value);
            case PARAM_VALUE:      return value(value);
            case PARAM_VERBOSE:    return verbose("true".equalsIgnoreCase(value));
            default:
                throw new IllegalArgumentException("Unknown " + parameterName + ": " + key);
        }
    }

    public void execute(String filename) throws CommandException {
        File file  = new File(filename);
        execute(file.isAbsolute() ? file : new File(basedir, filename));
    }

    public void execute(File file) throws CommandException {
        switch (command) {
            case "sign":
                new JsignTool().new Sign(parameterName)
                        .basedir(basedir)
                        .keystore(keystore)
                        .storepass(storepass)
                        .storetype(storetype != null ? KeyStoreType.valueOf(storetype) : null)
                        .alias(alias)
                        .keypass(keypass)
                        .keyfile(keyfile)
                        .certfile(certfile)
                        .alg(alg)
                        .tsaurl(tsaurl)
                        .tsmode(tsmode != null ? TimestampingMode.of(tsmode) : null)
                        .tsretries(tsretries)
                        .tsretrywait(tsretrywait)
                        .name(name)
                        .url(url)
                        .proxyUrl(proxySettings.url)
                        .proxyUser(proxySettings.username)
                        .proxyPass(proxySettings.password)
                        .nonProxyHosts(proxySettings.nonProxyHosts)
                        .replace(replace)
                        .lazy(lazy)
                        .encoding(encoding)
                        .detached(detached)
                        .execute(file);
                break;

            case "timestamp":
                new JsignTool().new Timestamp<>()
                        .tsaurl(tsaurl)
                        .tsmode(tsmode != null ? TimestampingMode.of(tsmode) : null)
                        .tsretries(tsretries)
                        .tsretrywait(tsretrywait)
                        .proxyUrl(proxySettings.url)
                        .proxyUser(proxySettings.username)
                        .proxyPass(proxySettings.password)
                        .nonProxyHosts(proxySettings.nonProxyHosts)
                        .replace(replace)
                        .execute(file);
                break;

            case "extract":
                new JsignTool().new Extract().format(format).execute(file);
                break;

            case "remove":
                new JsignTool().new Remove()
                        .alg(alg)
                        .name(name)
                        .execute(file);
                break;

            case "show":
                new JsignTool().new Show().verbose(verbose).execute(file);
                break;

            case "tag":
                new JsignTool().new Tag().value(value).execute(file);
                break;

            default:
                throw new IllegalArgumentException("Unknown command '" + command + "'");
        }
    }

    public void sign(String file) throws CommandException {
        execute(file);
    }

    public void sign(File file) throws CommandException {
        execute(file);
    }
}
