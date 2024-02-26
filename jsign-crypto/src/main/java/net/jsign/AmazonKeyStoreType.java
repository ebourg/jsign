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

import java.io.IOException;
import java.net.UnknownServiceException;
import java.security.Provider;

import org.kohsuke.MetaInfServices;

import net.jsign.jca.AmazonCredentials;
import net.jsign.jca.AmazonSigningService;
import net.jsign.jca.SigningServiceJcaProvider;

@MetaInfServices(KeyStoreType.class)
public class AmazonKeyStoreType extends AbstractKeyStoreType {

    @Override
    public String name() {
        return "AWS";
    }

    @Override
    public void validate(KeyStoreBuilder params) {
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
