/*
 * Copyright 2019 Red Hat, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.security.examples;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.wildfly.security.auth.server.IdentityCredentials;
import org.wildfly.security.credential.KeyPairCredential;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.credential.PublicKeyCredential;
import org.wildfly.security.credential.SecretKeyCredential;
import org.wildfly.security.credential.store.CredentialStore;
import org.wildfly.security.credential.store.CredentialStore.CredentialSourceProtectionParameter;
import org.wildfly.security.credential.store.CredentialStore.ProtectionParameter;
import org.wildfly.security.credential.store.WildFlyElytronCredentialStoreProvider;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.WildFlyElytronPasswordProvider;
import org.wildfly.security.password.interfaces.ClearPassword;

/**
 * Example demonstrating how a credential store can be created, populated and queried.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class CredentialStoreExample {

    private static final Provider CREDENTIAL_STORE_PROVIDER = new WildFlyElytronCredentialStoreProvider();
    private static final Provider PASSWORD_PROVIDER = new WildFlyElytronPasswordProvider();

    static {
        Security.addProvider(PASSWORD_PROVIDER);
        Security.addProvider(new BouncyCastleFipsProvider());
        Security.addProvider(new com.sun.crypto.provider.SunJCE());
    }

    private static void populateCredentialStore(final CredentialStore credentialStore) throws Exception {
        // Clear Password
        Password clearPassword = ClearPassword.createRaw(ClearPassword.ALGORITHM_CLEAR, "ExamplePassword".toCharArray());
        credentialStore.store("clearPassword", new PasswordCredential(clearPassword));
        credentialStore.flush();
    }

    private static void retrieveCredentials(final CredentialStore credentialStore) throws Exception {
        Password password = credentialStore.retrieve("clearPassword", PasswordCredential.class).getPassword();
    }

    public static void main(String[] args) throws Exception {

        /*
         * Create a ProtectionParameter for access to the store.
         */
        Password storePassword = ClearPassword.createRaw(ClearPassword.ALGORITHM_CLEAR, "password".toCharArray());
        ProtectionParameter protectionParameter = new CredentialSourceProtectionParameter(IdentityCredentials.NONE.withCredential(new PasswordCredential(storePassword)));
        // Get an instance of the CredentialStore
        CredentialStore credentialStore = CredentialStore.getInstance("KeyStoreCredentialStore", CREDENTIAL_STORE_PROVIDER);
        // Configure and Initialise the CredentialStore
        Map<String, String> configuration = new HashMap<>();
        configuration.put("modifiable", "true");
        configuration.put("create", "true");
	    configuration.put("location", "/home/rishabh/eap/test/examplekeystore.bcfks");
	    configuration.put("keyAlias", "exampleKeyAlias");
	    configuration.put("external","true");
	    configuration.put("keyStoreType","BCFKS");
	    configuration.put("externalPath","/home/rishabh/eap/test/hello.bcfks");
        credentialStore.initialize(configuration, protectionParameter);

       populateCredentialStore(credentialStore);

        System.out.println("************************************");
        System.out.println("Current Aliases: -");
        for (String alias : credentialStore.getAliases()) {
            System.out.print(" - ");
            System.out.println(alias);
        }
        System.out.println("************************************");

        retrieveCredentials(credentialStore);
    }

}
