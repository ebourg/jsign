/*
 * Copyright 2024 Björn Kautler
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

import net.jsign.jca.AmazonCredentials;
import net.jsign.jca.AmazonSigningService;
import net.jsign.jca.SigningServiceJcaProvider;
import org.kohsuke.MetaInfServices;

import java.io.IOException;
import java.net.UnknownServiceException;
import java.security.Provider;

import static net.jsign.JsignKeyStore.getCertificateStore;

/**
 * AWS Key Management Service (KMS). AWS KMS stores only the private key, the certificate must be provided
 * separately. The keystore parameter references the AWS region.
 *
 * <p>The AWS access key, secret key, and optionally the session token, are concatenated and used as
 * the storepass parameter; if the latter is not provided, Jsign attempts to fetch the credentials from
 * the environment variables (<code>AWS_ACCESS_KEY_ID</code>, <code>AWS_SECRET_ACCESS_KEY</code> and
 * <code>AWS_SESSION_TOKEN</code>) or from the IMDSv2 service when running on an AWS EC2 instance.</p>
 *
 * <p>In any case, the credentials must allow the following actions: <code>kms:ListKeys</code>,
 * <code>kms:DescribeKey</code> and <code>kms:Sign</code>.</p>
 */
@MetaInfServices(JsignKeyStore.class)
public class AwsKeyStore extends AbstractJsignKeyStore {
    @Override
    public String getType() {
        return "AWS";
    }

    @Override
    public void validate(KeyStoreBuilder params) throws IllegalArgumentException {
        if (params.keystore() == null) {
            throw new IllegalArgumentException("keystore " + params.parameterName() + " must specify the AWS region");
        }
        if (params.certfile() == null) {
            throw new IllegalArgumentException("certfile " + params.parameterName() + " must be set");
        }
    }

    @Override
    public Provider getProvider(KeyStoreBuilder params) {
        AmazonCredentials credentials;
        if (params.storepass() != null) {
            credentials = AmazonCredentials.parse(params.storepass());
        } else {
            try {
                credentials = AmazonCredentials.getDefault();
            } catch (UnknownServiceException e) {
                throw new IllegalArgumentException("storepass " + params.parameterName()
                        + " must specify the AWS credentials: <accessKey>|<secretKey>[|<sessionToken>]"
                        + ", when not running from an EC2 instance (" + e.getMessage() + ")", e);
            } catch (IOException e) {
                throw new RuntimeException("An error occurred while fetching temporary credentials from IMDSv2 service", e);
            }
        }

        return new SigningServiceJcaProvider(new AmazonSigningService(params.keystore(), credentials, getCertificateStore(params)));
    }
}
