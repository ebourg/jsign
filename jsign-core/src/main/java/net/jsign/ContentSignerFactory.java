package net.jsign;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;

interface HsmContentSigner {
    byte[] apply(ByteArrayOutputStream stream);
}

class ContentSignerFactory {
    static ContentSigner getContentSigner(final HsmContentSigner lambda, final String algorithm) {
        return new ContentSigner() {
            //This is to ensure that signature is created using the right data.
            ByteArrayOutputStream stream = new ByteArrayOutputStream();

            @Override
            public byte[] getSignature() {
                //Calling HSM here instead, the stream is the AttributeMap
                byte[] data = lambda.apply(stream);
                return data;
            }

            //Perhaps called by BouncyCastle library to provide the content
            @Override
            public OutputStream getOutputStream() {
                return stream;
            }

            @Override
            public AlgorithmIdentifier getAlgorithmIdentifier() {
                return new DefaultSignatureAlgorithmIdentifierFinder().find(algorithm);
            }
        };
    }
}