/**
 * Copyright 2019 Emmanuel Bourg and contributors
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

import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.ServiceLoader;
import java.util.function.Supplier;
import java.util.stream.Stream;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.PKCS7ProcessableObject;

import net.jsign.asn1.authenticode.AuthenticodeObjectIdentifiers;
import net.jsign.spi.SignableProvider;

/**
 * A file that can be signed with Authenticode.
 *
 * @author Emmanuel Bourg
 */
public interface Signable extends Closeable {

    /**
     * Creates the ContentInfo or EncapsulatedContentInfo structure to be signed.
     *
     * @param digestAlgorithm the digest algorithm to use
     * @return the ContentInfo or EncapsulatedContentInfo structure
     * @throws IOException if an I/O error occurs
     * @since 7.0
     */
    default CMSTypedData createSignedContent(DigestAlgorithm digestAlgorithm) throws IOException {
        return new PKCS7ProcessableObject(AuthenticodeObjectIdentifiers.SPC_INDIRECT_DATA_OBJID, createIndirectData(digestAlgorithm));
    }

    /**
     * Creates the ContentInfo structure to be signed.
     *
     * @param digestAlgorithm the digest algorithm to use
     * @return the ContentInfo structure in ASN.1 format
     * @throws IOException if an I/O error occurs
     * @since 4.2
     * @deprecated Use {@link #createSignedContent(DigestAlgorithm)} instead
     */
    default ContentInfo createContentInfo(DigestAlgorithm digestAlgorithm) throws IOException {
        return new ContentInfo(AuthenticodeObjectIdentifiers.SPC_INDIRECT_DATA_OBJID, createIndirectData(digestAlgorithm));
    }

    /**
     * Computes the digest of the file.
     * 
     * @param digest the message digest to update
     * @return the digest of the file
     * @throws IOException if an I/O error occurs
     * @deprecated Use {@link #computeDigest(DigestAlgorithm)} instead
     */
    default byte[] computeDigest(MessageDigest digest) throws IOException {
        return computeDigest(DigestAlgorithm.of(digest.getAlgorithm()));
    }

    /**
     * Computes the digest of the file.
     *
     * @param digestAlgorithm the digest algorithm to use
     * @return the digest of the file
     * @throws IOException if an I/O error occurs
     * @since 6.0
     */
    default byte[] computeDigest(DigestAlgorithm digestAlgorithm) throws IOException {
        return computeDigest(digestAlgorithm.getMessageDigest());
    }

    /**
     * Creates the SpcIndirectDataContent structure containing the digest of the file.
     * 
     * @param digestAlgorithm the digest algorithm to use
     * @return the SpcIndirectDataContent structure in ASN.1 format
     * @throws IOException if an I/O error occurs
     */
    ASN1Object createIndirectData(DigestAlgorithm digestAlgorithm) throws IOException;

    /**
     * Creates the signed attributes to include in the signature.
     *
     * @param certificate the signing certificate
     * @since 7.0
     */
    default List<Attribute> createSignedAttributes(X509Certificate certificate) throws CertificateEncodingException {
        return new ArrayList<>();
    }

    /**
     * Checks if the specified certificate is suitable for signing the file.
     *
     * @param certificate the certificate to validate
     * @throws IOException if an I/O error occurs
     * @throws IllegalArgumentException if the certificate doesn't match the publisher identity
     * @since 7.0
     */
    default void validate(Certificate certificate) throws IOException, IllegalArgumentException {
    }

    /**
     * Returns the Authenticode signatures on the file.
     * 
     * @return the signatures
     * @throws IOException if an I/O error occurs
     */
    List<CMSSignedData> getSignatures() throws IOException;

    /**
     * Sets the signature of the file, overwriting the previous one.
     * 
     * @param signature the signature to put, or null to remove the signature
     * @throws IOException if an I/O error occurs
     */
    void setSignature(CMSSignedData signature) throws IOException;

    /**
     * Saves the file.
     * 
     * @throws IOException if an I/O error occurs
     */
    void save() throws IOException;

    /**
     * Returns a signable object for the file specified.
     *
     * @param file the file that is intended to be signed
     * @return the signable object for the specified file
     * @throws IOException if an I/O error occurs
     * @throws UnsupportedOperationException if the file specified isn't supported
     */
    static Signable of(File file) throws IOException {
        return of(file, null);
    }

    /**
     * Returns a signable object for the file specified.
     *
     * @param file     the file that is intended to be signed
     * @param encoding the character encoding (for text files only).
     *                 If the file has a byte order mark this parameter is ignored.
     * @return the signable object for the specified file
     * @throws IOException if an I/O error occurs
     * @throws UnsupportedOperationException if the file specified isn't supported
     */
    static Signable of(File file, Charset encoding) throws IOException {
        // look for SignableProvider implementations in the classloader that loaded the Jsign classes and in the current classloader
        Supplier<ServiceLoader<SignableProvider>> loaders1 = () -> ServiceLoader.load(SignableProvider.class, Signable.class.getClassLoader());
        Supplier<ServiceLoader<SignableProvider>> loaders2 = () -> ServiceLoader.load(SignableProvider.class);

        for (Supplier<ServiceLoader<SignableProvider>> loaders : Arrays.asList(loaders1, loaders2)) {
            for (SignableProvider provider : loaders.get()) {
                if (provider.isSupported(file)) {
                    return provider.create(file, encoding);
                }
            }
        }

        throw new UnsupportedOperationException("Unsupported file: " + file);
    }
}
