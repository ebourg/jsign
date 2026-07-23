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

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Logger;

import org.apache.commons.collections4.functors.AndPredicate;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1UTF8String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.operator.DefaultAlgorithmNameFinder;
import org.bouncycastle.util.encoders.Hex;

import net.jsign.asn1.authenticode.AuthenticodeObjectIdentifiers;
import net.jsign.asn1.authenticode.SpcLink;
import net.jsign.asn1.authenticode.SpcSpOpusInfo;
import net.jsign.timestamp.Timestamper;
import net.jsign.timestamp.TimestampingMode;

/**
 * High level API for executing Jsign commands.
 *
 * <p>Examples:</p>
 *
 * <pre>
 *  JsignTool.sign()
 *           .keystore("keystore.p12")
 *           .storepass("password")
 *           .alias("test")
 *           .name("My Application")
 *           .tsaurl("http://timestamp.sectigo.com")
 *           .execute(file);
 *
 *   JsignTool.tag().value("userid:1234-ABCD-5678-EFGH").execute(file);
 *
 *   JsignTool.extract().format("PEM").execute(file);
 *
 *   JsignTool.remove().execute(file);
 * </pre>
 *
 * @since 8.0
 */
public final class JsignTool {

    JsignTool() {
    }

    /**
     * Creates a builder for the {@code sign} command.
     */
    public static Sign sign() {
        return new JsignTool().new Sign("parameter");
    }

    /**
     * Creates a builder for the {@code tag} command.
     */
    public static Tag tag() {
        return new JsignTool().new Tag();
    }

    /**
     * Creates a builder for the {@code extract} command.
     */
    public static Extract extract() {
        return new JsignTool().new Extract();
    }

    /**
     * Creates a builder for the {@code timestamp} command.
     */
    public static Timestamp<?> timestamp() {
        return new JsignTool().new Timestamp<>();
    }

    /**
     * Creates a builder for the {@code remove} command.
     */
    public static Remove remove() {
        return new JsignTool().new Remove();
    }

    /**
     * Creates a builder for the {@code show} command.
     */
    public static Show show() {
        return new JsignTool().new Show();
    }

    abstract class Command<T extends Command<?>> {

        protected final Logger log = Logger.getLogger(getClass().getName());

        File basedir;

        /** The name used to refer to a configuration parameter */
        String parameterName = "parameter";

        public Command() {
        }

        T basedir(File basedir) {
            this.basedir = basedir;
            return (T) this;
        }

        /**
         * Executes the command on the specified files.
         *
         * @param files the files to execute the command on
         */
        public void execute(File... files) throws Exception {
            if (files == null || files.length == 0) {
                throw new IllegalArgumentException("No file specified");
            }

            for (File file : files) {
                execute(file);
            }
        }

        abstract void execute(File file) throws Exception;
    }

    /**
     * Command for signing files.
     */
    public class Sign extends Timestamp<Sign> {

        private AuthenticodeSigner signer;

        private final KeyStoreBuilder ksparams;
        private String alias;

        private String name;
        private String url;
        private boolean lazy;
        private Charset encoding;
        private boolean detached;

        Sign(String parameterName) {
            this.parameterName = parameterName;
            this.ksparams = new KeyStoreBuilder(parameterName);
        }

        @Override
        Sign basedir(File basedir) {
            ksparams.setBaseDir(basedir);
            return (Sign) super.basedir(basedir);
        }

        void reset() {
            signer = null;
        }

        @Override
        public Sign replace(boolean replace) {
            super.replace(replace);
            return this;
        }

        @Override
        public Sign replace() {
            super.replace();
            reset();
            return this;
        }

        /**
         * Sets the keystore file, the SunPKCS11 configuration file, the cloud keystore name, or the card/token name.
         */
        public Sign keystore(String keystore) {
            ksparams.keystore(keystore);
            reset();
            return this;
        }

        /**
         * Sets the keystore file or the SunPKCS11 configuration file.
         */
        public Sign keystore(File keystore) {
            ksparams.keystore(keystore);
            reset();
            return this;
        }

        /**
         * Sets the password to open the keystore.
         */
        public Sign storepass(String storepass) {
            ksparams.storepass(storepass);
            reset();
            return this;
        }

        /**
         * Sets the type of the keystore.
         */
        public Sign storetype(KeyStoreType storetype) {
            ksparams.storetype(storetype);
            reset();
            return this;
        }

        /**
         * Sets the alias of the certificate used for signing in the keystore.
         */
        public Sign alias(String alias) {
            this.alias = alias;
            reset();
            return this;
        }

        /**
         * Sets the password of the private key. When using a keystore, this parameter can be omitted if the keystore shares the same password.
         */
        public Sign keypass(String keypass) {
            ksparams.keypass(keypass);
            reset();
            return this;
        }

        /**
         * Sets the file containing the private key. PEM and PVK files are supported.
         */
        public Sign keyfile(String keyfile) {
            ksparams.keyfile(keyfile);
            reset();
            return this;
        }

        /**
         * Sets the file containing the private key. PEM and PVK files are supported.
         */
        public Sign keyfile(File keyfile) {
            ksparams.keyfile(keyfile);
            reset();
            return this;
        }

        /**
         * Sets the file containing the PKCS#7 certificate chain (.p7b or .spc files).
         */
        public Sign certfile(String certfile) {
            ksparams.certfile(certfile);
            reset();
            return this;
        }

        /**
         * Sets the file containing the PKCS#7 certificate chain (.p7b or .spc files).
         */
        public Sign certfile(File certfile) {
            ksparams.certfile(certfile);
            reset();
            return this;
        }

        @Override
        public Sign alg(DigestAlgorithm alg) {
            reset();
            return super.alg(alg);
        }

        @Override
        public Sign alg(String alg) {
            reset();
            return super.alg(alg);
        }

        /**
         * Sets the name of the application.
         */
        public Sign name(String name) {
            this.name = name;
            reset();
            return this;
        }

        /**
         * Sets the URL of the application.
         */
        public Sign url(String url) {
            this.url = url;
            reset();
            return this;
        }

        /**
         * Skip files that are already signed.
         */
        public Sign lazy() {
            return lazy(true);
        }

        /**
         * Skip files that are already signed.
         */
        public Sign lazy(boolean lazy) {
            this.lazy = lazy;
            return this;
        }

        /**
         * Sets the encoding of the script to be signed (UTF-8 by default, or the encoding specified by the byte order mark if there is one).
         */
        public Sign encoding(String encoding) {
            this.encoding = encoding != null ? Charset.forName(encoding) : null;
            return this;
        }

        /**
         * Tells that a detached signature should be generated or reused.
         */
        public Sign detached() {
            return detached(true);
        }

        /**
         * Tells if a detached signature should be generated or reused.
         */
        public Sign detached(boolean detached) {
            this.detached = detached;
            return this;
        }

        private AuthenticodeSigner build() throws CommandException {
            try {
                proxySettings.initializeProxy();
            } catch (Exception e) {
                throw new CommandException("Couldn't initialize proxy", e);
            }

            KeyStore ks;
            try {
                ks = ksparams.build();
            } catch (KeyStoreException e) {
                throw new CommandException("Failed to load the keystore " + (ksparams.keystore() != null ? ksparams.keystore() : ""), e);
            }
            KeyStoreType storetype = ksparams.storetype();
            Provider provider = ksparams.provider();

            Set<String> aliases = null;
            if (alias == null) {
                // guess the alias if there is only one in the keystore
                try {
                    aliases = storetype.getAliases(ks);
                } catch (KeyStoreException e) {
                    throw new CommandException(e.getMessage(), e);
                }

                if (aliases.isEmpty()) {
                    throw new CommandException("No certificate found in the keystore " + (provider != null ? provider.getName() : ksparams.keystore()));
                } else if (aliases.size() == 1) {
                    alias = aliases.iterator().next();
                } else {
                    throw new CommandException("alias " + parameterName + " must be set to select a certificate (available aliases: " + String.join(", ", aliases) + ")");
                }
            }

            Certificate[] chain;
            if (ksparams.certfile() != null) {
                // replace the certificate chain from the keystore with the complete chain from file
                try {
                    chain = CertificateUtils.loadCertificateChain(ksparams.certfile());
                } catch (Exception e) {
                    throw new CommandException("Failed to load the certificate from " + ksparams.certfile(), e);
                }
            } else {
                try {
                    chain = ks.getCertificateChain(alias);
                } catch (KeyStoreException e) {
                    throw new CommandException(e.getMessage(), e);
                }
                if (chain == null) {
                    String message = "No certificate found under the alias '" + alias + "' in the keystore " + (provider != null ? provider.getName() : ksparams.keystore());
                    if (aliases == null) {
                        try {
                            aliases = new LinkedHashSet<>(Collections.list(ks.aliases()));
                            if (aliases.isEmpty()) {
                                message = "No certificate found in the keystore " + (provider != null ? provider.getName() : ksparams.keystore());
                            } else if (aliases.contains(alias)) {
                                message = "The keystore password must be specified";
                            } else {
                                message += " (available aliases: " + String.join(", ", aliases) + ")";
                            }
                        } catch (KeyStoreException e) {
                            message += " (couldn't load the list of available aliases: " + e.getMessage() + ")";
                        }
                    }
                    throw new CommandException(message);
                }
            }

            String keypass = ksparams.keypass();
            char[] password = keypass != null ? keypass.toCharArray() : new char[0];

            PrivateKey privateKey;
            try {
                privateKey = (PrivateKey) ks.getKey(alias, password);
            } catch (Exception e) {
                throw new CommandException("Failed to retrieve the private key from the keystore", e);
            }

            if (alg != null && DigestAlgorithm.of(alg) == null) {
                throw new CommandException("The digest algorithm " + alg + " is not supported");
            }

            // enable timestamping with Azure Artifact Signing
            if (tsaurl == null && storetype == KeyStoreType.TRUSTEDSIGNING) {
                tsaurl = "http://timestamp.acs.microsoft.com/";
                tsmode = TimestampingMode.RFC3161;
                tsretries = 3;
            }

            // configure the signer
            return new AuthenticodeSigner(chain, privateKey)
                    .withProgramName(name)
                    .withProgramURL(url)
                    .withDigestAlgorithm(DigestAlgorithm.of(alg))
                    .withSignatureProvider(provider)
                    .withSignaturesReplaced(replace)
                    .withTimestamping(tsaurl != null || tsmode != null)
                    .withTimestampingMode(tsmode != null ? tsmode : TimestampingMode.AUTHENTICODE)
                    .withTimestampingRetries(tsretries)
                    .withTimestampingRetryWait(tsretrywait)
                    .withTimestampingAuthority(tsaurl != null ? tsaurl.split(",") : null);
        }

        void execute(File file) throws CommandException {
            if (file == null) {
                throw new CommandException("No file specified");
            }
            if (!file.exists()) {
                throw new CommandException("The file " + file + " couldn't be found");
            }

            try (Signable signable = Signable.of(file, encoding)) {
                File detachedSignature = getDetachedSignature(file);
                if (detached && detachedSignature.exists()) {
                    try {
                        log.info("Attaching Authenticode signature to " + file);
                        attach(signable, detachedSignature);
                    } catch (Exception e) {
                        throw new CommandException("Couldn't attach the signature to " + file, e);
                    }

                } else {
                    if (lazy && !signable.getSignatures().isEmpty()) {
                        log.info("Skipping already signed file " + file);
                        return;
                    }

                    if (signer == null) {
                        signer = build();
                    }

                    log.info("Adding Authenticode signature to " + file);
                    signer.sign(signable);

                    if (detached) {
                        detach(signable, detachedSignature, "DER");
                    }
                }

            } catch (UnsupportedOperationException | IllegalArgumentException e) {
                throw new CommandException(e.getMessage(), e);
            } catch (CommandException e) {
                throw e;
            } catch (Exception e) {
                throw new CommandException("Couldn't sign " + file, e);
            }
        }
    }

    /**
     * Command for adding a timestamp to a signed file.
     */
    public class Timestamp<T extends Timestamp<?>> extends Command {

        String tsaurl;
        TimestampingMode tsmode;
        int tsretries = -1;
        int tsretrywait = -1;
        String alg;
        ProxySettings proxySettings = new ProxySettings();
        boolean replace;

        void reset() {
        }

        /**
         * Sets the digest algorithm.
         */
        public T alg(String alg) {
            this.alg = alg;
            return (T) this;
        }

        /**
         * Sets the digest algorithm.
         */
        public T alg(DigestAlgorithm alg) {
            this.alg = alg != null ? alg.name() : null;
            return (T) this;
        }

        /**
         * Sets the URL of the timestamping authority.
         * Several URLs separated by a comma can be specified to fallback on alternative servers.
         */
        public T tsaurl(String tsaurl) {
            this.tsaurl = tsaurl;
            reset();
            return (T) this;
        }

        /**
         * Sets the timestamping mode ({@link TimestampingMode#AUTHENTICODE} or {@link TimestampingMode#RFC3161}).
         */
        public T tsmode(TimestampingMode tsmode) {
            this.tsmode = tsmode;
            reset();
            return (T) this;
        }

        /**
         * Sets the number of retries for timestamping.
         */
        public T tsretries(int tsretries) {
            this.tsretries = tsretries;
            reset();
            return (T) this;
        }

        /**
         * Sets the number of seconds to wait between timestamping retries.
         */
        public T tsretrywait(int tsretrywait) {
            this.tsretrywait = tsretrywait;
            reset();
            return (T) this;
        }

        /**
         * Sets the URL of the HTTP proxy.
         */
        public T proxyUrl(String proxyUrl) {
            proxySettings.url  = proxyUrl;
            reset();
            return (T) this;
        }

        /**
         * Sets the user for the HTTP proxy.
         */
        public T proxyUser(String proxyUser) {
            proxySettings.username  = proxyUser;
            reset();
            return (T) this;
        }

        /**
         * Sets the password for the HTTP proxy user.
         */
        public T proxyPass(String proxyPass) {
            proxySettings.password  = proxyPass;
            reset();
            return (T) this;
        }

        /**
         * Sets the hosts that bypass the HTTP proxy.
         */
        public T nonProxyHosts(String nonProxyHosts) {
            proxySettings.nonProxyHosts = nonProxyHosts;
            reset();
            return (T) this;
        }

        /**
         * Tells if the previous timestamps should be replaced.
         */
        public Timestamp<?> replace(boolean replace) {
            this.replace = replace;
            return this;
        }

        /**
         * Tells that the previous timestamps should be replaced.
         */
        public Timestamp<?> replace() {
            return replace(true);
        }

        void execute(File file) throws CommandException {
            if (!file.exists()) {
                throw new CommandException("Couldn't find " + file);
            }

            try {
                proxySettings.initializeProxy();
            } catch (Exception e) {
                throw new CommandException("Couldn't initialize proxy", e);
            }

            try (Signable signable = Signable.of(file)) {
                if (signable.getSignatures().isEmpty()) {
                    throw new CommandException("No signature found in " + file);
                }

                Timestamper timestamper = Timestamper.create(tsmode != null ? tsmode : TimestampingMode.AUTHENTICODE);
                timestamper.setRetries(tsretries);
                timestamper.setRetryWait(tsretrywait);
                if (tsaurl != null) {
                    timestamper.setURLs(tsaurl.split(","));
                }
                DigestAlgorithm digestAlgorithm = alg != null ? DigestAlgorithm.of(alg) : DigestAlgorithm.getDefault();

                List<CMSSignedData> signatures = new ArrayList<>();
                for (CMSSignedData signature : signable.getSignatures()) {
                    SignerInformation signerInformation = signature.getSignerInfos().iterator().next();
                    SignerId signerId = signerInformation.getSID();
                    X509CertificateHolder certificate = (X509CertificateHolder) signature.getCertificates().getMatches(signerId).iterator().next();

                    String digestAlgorithmName = new DefaultAlgorithmNameFinder().getAlgorithmName(signerInformation.getDigestAlgorithmID());
                    String keyAlgorithmName = new DefaultAlgorithmNameFinder().getAlgorithmName(new ASN1ObjectIdentifier(signerInformation.getEncryptionAlgOID()));
                    String name = digestAlgorithmName + "/" + keyAlgorithmName + " signature from '" + certificate.getSubject() + "'";

                    if (SignatureUtils.isTimestamped(signature) && !replace) {
                        log.fine(name + " already timestamped");
                        signatures.add(signature);
                        continue;
                    }

                    boolean expired = certificate.getNotAfter().before(new Date());
                    if (expired) {
                        log.fine(name + " is expired, skipping");
                        signatures.add(signature);
                        continue;
                    }

                    log.info("Adding timestamp to " + name);
                    signature = SignatureUtils.removeTimestamp(signature);
                    signature = timestamper.timestamp(digestAlgorithm, signature);

                    signatures.add(signature);
                }

                signable.setSignatures(signatures);
                signable.save();
            } catch (IOException | CMSException e) {
                throw new CommandException("Couldn't timestamp " + file, e);
            }
        }
    }

    /**
     * Command for tagging a signed file with an unauthenticated attribute.
     */
    public class Tag extends Command {

        private String value;

        /**
         * Sets the value of the unsigned attribute. The value is either:
         * <ul>
         *   <li>a string (such as a user id, a license key or a JWT token)</li>
         *   <li>the name of the file to include, prefixed with <code>file:</code>
         *   <li>a binary value in hexadecimal format, prefixed with <code>0x</code>
         * </ul>
         */
        public Tag value(String value) {
            this.value = value;
            return this;
        }

        void execute(File file) throws CommandException {
            if (!file.exists()) {
                throw new CommandException("Couldn't find " + file);
            }

            try (Signable signable = Signable.of(file)) {
                List<CMSSignedData> signatures = signable.getSignatures();
                if (signatures.isEmpty()) {
                    throw new CommandException("No signature found in " + file);
                }

                log.info("Adding tag to " + file);
                signatures.set(0, SignatureUtils.addUnsignedAttribute(signatures.get(0), AuthenticodeObjectIdentifiers.JSIGN_UNSIGNED_DATA_OBJID, getTagValue()));
                signable.setSignatures(signatures);
                signable.save();
            } catch (CommandException e) {
                throw e;
            } catch (Exception e) {
                throw new CommandException("Couldn't modify the signature of " + file, e);
            }
        }

        private ASN1Encodable getTagValue() throws IOException {
            if (value == null) {
                byte[] array = new byte[1024];
                String begin = "-----BEGIN TAG-----";
                System.arraycopy(begin.getBytes(), 0, array, 0, begin.length());
                String end = "-----END TAG-----";
                System.arraycopy(end.getBytes(), 0, array, array.length - end.length(), end.length());
                return new DEROctetString(array);

            } else if (value.startsWith("0x")) {
                byte[] array = Hex.decode(value.substring(2));
                return new DEROctetString(array);

            } else if (value.startsWith("file:")) {
                byte[] array = Files.readAllBytes(new File(value.substring("file:".length())).toPath());
                return new DEROctetString(array);

            } else {
                return new DERUTF8String(value);
            }
        }
    }

    /**
     * Command for extracting the signatures of a signed file.
     */
    public class Extract extends Command {

        private String format;

        /**
         * Sets the output format of the signature ({@code DER} or {@code PEM}).
         */
        public Extract format(String format) {
            this.format = format;
            return this;
        }

        void execute(File file) throws CommandException {
            if (!file.exists()) {
                throw new CommandException("Couldn't find " + file);
            }

            try (Signable signable = Signable.of(file)) {
                List<CMSSignedData> signatures = signable.getSignatures();
                if (signatures.isEmpty()) {
                    throw new CommandException("No signature found in " + file);
                }

                File detachedSignature = getDetachedSignature(file);
                if ("PEM".equalsIgnoreCase(format)) {
                    detachedSignature = new File(detachedSignature.getParentFile(), detachedSignature.getName() + ".pem");
                }
                log.info("Extracting signature to " + detachedSignature);
                detach(signable, detachedSignature, format);
            } catch (UnsupportedOperationException | IllegalArgumentException e) {
                throw new CommandException(e.getMessage(), e);
            } catch (CommandException e) {
                throw e;
            } catch (Exception e) {
                throw new CommandException("Couldn't extract the signature from " + file, e);
            }
        }
    }

    /**
     * Command for removing the signatures of a file.
     */
    public class Remove extends Command {

        private String alg;
        private String name;

        /**
         * Sets the digest algorithm of the signatures to remove.
         */
        public Remove alg(DigestAlgorithm alg) {
            this.alg = alg.name();
            return this;
        }

        /**
         * Sets the digest algorithm of the signatures to remove.
         */
        public Remove alg(String alg) {
            this.alg = alg;
            return this;
        }

        /**
         * Sets the certificate name used to select the signatures to remove (partial match).
         */
        public Remove name(String name) {
            this.name = name;
            return this;
        }

        public void execute(File file) throws CommandException {
            if (!file.exists()) {
                throw new CommandException("Couldn't find " + file);
            }

            try (Signable signable = Signable.of(file)) {
                List<CMSSignedData> signatures = signable.getSignatures();
                if (signatures.isEmpty()) {
                    log.severe("No signature found in " + file);
                    return;
                }

                DigestAlgorithm removedAlgorithm = alg != null ? DigestAlgorithm.of(alg) : null;
                if (alg != null && removedAlgorithm == null) {
                    throw new CommandException("The digest algorithm " + alg + " is not supported");
                }

                int signatureCount = signatures.size();

                signatures.removeIf(new AndPredicate<>(
                        signature -> alg == null || signature.getSignerInfos().iterator().next().getDigestAlgOID().equals(removedAlgorithm.oid.getId()),
                        signature -> {
                            SignerInformation signer = signature.getSignerInfos().iterator().next();
                            X509CertificateHolder cert = (X509CertificateHolder) signature.getCertificates().getMatches(signer.getSID()).iterator().next();
                            return name == null || formatName(cert.getSubject(), false).toLowerCase().contains(name.toLowerCase());
                        }));

                if (signatures.size() == signatureCount) {
                    List<String> criteria = new ArrayList<>();
                    if (name != null) {
                        criteria.add("the name '" + name + "'");
                    }
                    if (alg != null) {
                        criteria.add("the digest algorithm " + alg);
                    }

                    log.info("No signature matching " + String.join(" and ", criteria) + " found in " + file);
                    return;
                }

                int removedCount = signatureCount - signatures.size();
                log.info("Removing " + removedCount + " signature" + (removedCount > 1 ? "s" : "") + " from " + file);

                signable.setSignatures(signatures);
                signable.save();
            } catch (UnsupportedOperationException | IllegalArgumentException e) {
                throw new CommandException(e.getMessage(), e);
            } catch (Exception e) {
                throw new CommandException("Couldn't remove the signature from " + file, e);
            }
        }
    }

    /**
     * Command for displaying the signatures of a file.
     */
    public class Show extends Command {

        private boolean verbose;

        /**
         * Prints more information.
         */
        public Show verbose(boolean verbose) {
            this.verbose = verbose;
            return this;
        }

        void execute(File file) throws CommandException {
            if (!file.exists()) {
                throw new CommandException("Couldn't find " + file);
            }

            AnsiFormatter ansiFormatter = new AnsiFormatter();
            log.setFilter(record -> {
                record.setMessage(ansiFormatter.format(record.getMessage()));
                return true;
            });

            try (Signable signable = Signable.of(file)) {
                List<CMSSignedData> signatures = signable.getSignatures();
                if (signatures.isEmpty()) {
                    log.info("No signature found in " + (verbose ? file.getAbsolutePath() : file.getName()));
                    return;
                }

                log.info("Signature" + (signatures.size() > 1 ? "s" : "") + " of " + (verbose ? file.getAbsolutePath() : file.getName()) + ":");
                log.info("");

                DateFormat datetimeFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss z");
                DateFormat dateFormat = verbose ? datetimeFormat : new SimpleDateFormat("yyyy-MM-dd");

                for (int i = 0; i < signatures.size(); i++) {
                    CMSSignedData signature = signatures.get(i);
                    SignerInformation signer = signature.getSignerInfos().iterator().next();
                    DigestInfo digestInfo = SignatureUtils.getDigestInfo(signature);
                    X509CertificateHolder cert = (X509CertificateHolder) signature.getCertificates().getMatches(signer.getSID()).iterator().next();

                    boolean expired = cert.getNotAfter().before(new Date());
                    long daysLeft = Duration.between(Instant.now(), cert.getNotAfter().toInstant()).toDays();

                    if (signatures.size() > 1) {
                        log.info("Signature #" + (i + 1));
                    }
                    if (digestInfo != null) {
                        DigestAlgorithm digestAlgorithm = DigestAlgorithm.of(signer.getDigestAlgorithmID().getAlgorithm());
                        byte[] computedDigest = signable.computeDigest(digestAlgorithm);
                        boolean matches = Arrays.equals(computedDigest, digestInfo.getDigest());
                        log.info("  <b>Digest:</b>          (" + digestAlgorithm.id + ") " + Hex.toHexString(digestInfo.getDigest()) + (matches ? " (<green>matches</green>)" : " (<red>mismatches</red>)"));
                        if (!matches) {
                            log.info("  <b>Expected Digest:</b> (" + digestAlgorithm.id + ") " + Hex.toHexString(computedDigest));
                        }
                    }

                    Date timestamp = SignatureUtils.getTimestampDate(signature);
                    if (timestamp != null) {
                        X509CertificateHolder timestampCertificate = SignatureUtils.getTimestampCertificate(signature);
                        log.info("  <b>Timestamp:</b>       " + datetimeFormat.format(timestamp) + " (" + formatName(timestampCertificate.getSubject(), verbose) + ")");
                    }

                    SpcSpOpusInfo spOpusInfo = SignatureUtils.getSpcSpOpusInfo(signature);
                    if (spOpusInfo != null) {
                        if (spOpusInfo.getProgramName() != null && !spOpusInfo.getProgramName().trim().isEmpty()) {
                            log.info("  <b>Program Name:</b>    " + spOpusInfo.getProgramName());
                        }
                        SpcLink moreInfo = spOpusInfo.getMoreInfo();
                        if (moreInfo != null && moreInfo.getUrl() != null && !moreInfo.getUrl().trim().isEmpty()) {
                            log.info("  <b>URL:</b>             " + moreInfo.getUrl());
                        }
                    }

                    String tag = formatTag(SignatureUtils.getTag(signature));
                    if (tag != null) {
                        log.info("  <b>Tag:</b>             " + tag.trim());
                    }

                    log.info("  <b>Certificate</b>");
                    log.info("    <b>Subject:</b>       " + formatName(cert.getSubject(), verbose));
                    log.info("    <b>Issuer:</b>        " + formatName(cert.getIssuer(), verbose));
                    log.info("    <b>Key:</b>           " + getKeyAlgorithm(cert));
                    log.info("    <b>Validity:</b>      " + dateFormat.format(cert.getNotBefore()) + " - " + dateFormat.format(cert.getNotAfter()) + " (" + (expired ? "expired" : daysLeft + " days left") + ")");
                    log.info("    <b>Serial:</b>        " + String.format("%032x", cert.getSerialNumber()));
                    log.info("");
                }
            } catch (Exception e) {
                throw new CommandException("Couldn't show the signatures of" + file, e);
            }
        }

        /**
         * Returns the algorithm of the public key of the certificate (for example "RSA 2048" or "EC 384").
         */
        private String getKeyAlgorithm(X509CertificateHolder certificate) throws IOException, CertificateException {
            X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(certificate.getEncoded()));
            PublicKey publicKey = cert.getPublicKey();

            if (publicKey instanceof RSAPublicKey) {
                return "RSA " + ((RSAPublicKey) publicKey).getModulus().bitLength();
            } else if (publicKey instanceof ECPublicKey) {
                return "EC " + (((ECPublicKey) publicKey).getParams()).getCurve().getField().getFieldSize();
            } else {
                return publicKey.getAlgorithm();
            }
        }

        /**
         * Formats the value of the unsigned tag.
         */
        private String formatTag(ASN1Encodable value) {
            if (value != null) {
                if (value instanceof ASN1UTF8String) {
                    return ((ASN1UTF8String) value).getString();
                }

                if (value instanceof DEROctetString) {
                    int limit = 100;
                    byte[] bytes = ((DEROctetString) value).getOctets();
                    return "(" + bytes.length + " bytes) " + new String(bytes).substring(0, limit) + (bytes.length > limit ? " ... (truncated)" : "");
                }
            }
            return null;
        }
    }

    private static File getDetachedSignature(File file) {
        return new File(file.getParentFile(), file.getName() + ".sig");
    }

    private static void attach(Signable signable, File detachedSignature) throws IOException {
        byte[] signatureBytes = Files.readAllBytes(detachedSignature.toPath());
        signable.setSignatures(SignatureUtils.getSignatures(signatureBytes));
        signable.save();
        // todo warn if the hashes don't match
    }

    private static void detach(Signable signable, File detachedSignature, String format) throws IOException {
        List<CMSSignedData> signatures = signable.getSignatures();

        // ensure the secondary signatures are nested in the first one (for EFI files)
        CMSSignedData signedData = signatures.get(0);
        if (signatures.size() > 1) {
            List<CMSSignedData> nestedSignatures = signatures.subList(1, signatures.size());
            signedData = SignatureUtils.addNestedSignature(signedData, true, nestedSignatures.toArray(new CMSSignedData[0]));
        }

        byte[] content = signedData.toASN1Structure().getEncoded("DER");
        if (format == null || "DER".equalsIgnoreCase(format)) {
            Files.write(detachedSignature.toPath(), content);
        } else if ("PEM".equalsIgnoreCase(format)) {
            try (FileWriter out = new FileWriter(detachedSignature)) {
                String encoded = Base64.getEncoder().encodeToString(content);
                out.write("-----BEGIN PKCS7-----\n");
                for (int i = 0; i < encoded.length(); i += 64) {
                    out.write(encoded.substring(i, Math.min(i + 64, encoded.length())));
                    out.write('\n');
                }
                out.write("-----END PKCS7-----\n");
            }
        } else {
            throw new IllegalArgumentException("Unknown output format '" + format + "'");
        }
    }

    /**
     * Formats the X500 name:
     * <ul>
     *   <li>in normal mode, returns only the common name (CN)</li>
     *   <li>in verbose mode, returns the full name in LDAP order (starting with the common name)</li>
     * </ul>
     */
    private static String formatName(X500Name name, boolean verbose) {
        if (verbose) {
            return new X500Name(new BCStyle() {
                public String toString(X500Name name) {
                    StringBuilder buf = new StringBuilder();
                    RDN[] rdns = name.getRDNs();
                    for (int i = rdns.length - 1; i >= 0; i--) {
                        if (i != rdns.length - 1) {
                            buf.append(", ");
                        }
                        IETFUtils.appendRDN(buf, rdns[i], defaultSymbols);
                    }
                    return buf.toString();
                }
            }, name.getRDNs()).toString().replaceAll("\\\\,", ",");
        } else {
            return name.getRDNs(BCStyle.CN)[0].getFirst().getValue().toString();
        }
    }
}
