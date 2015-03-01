/* 
 * ====================
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 * 
 * Copyright 2008-2009 Sun Microsystems, Inc. All rights reserved.
 * 
 * The contents of this file are subject to the terms of the Common Development
 * and Distribution License("CDDL") (the "License").  You may not use this file
 * except in compliance with the License.
 * 
 * You can obtain a copy of the License at
 * http://opensource.org/licenses/cddl1.php
 * See the License for the specific language governing permissions and limitations
 * under the License.
 * 
 * When distributing the Covered Code, include this CDDL Header Notice in each file
 * and include the License file at http://opensource.org/licenses/cddl1.php.
 * If applicable, add the following below this CDDL Header, with the fields
 * enclosed by brackets [] replaced by your own identifying information:
 * "Portions Copyrighted [year] [name of copyright owner]"
 * ====================
 * Portions Copyrighted 2011 ConnId.
 */
package net.tirasa.connid.bundles.ldap;

import static org.junit.Assert.fail;

import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.util.List;
import org.identityconnectors.common.IOUtil;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.api.APIConfiguration;
import org.identityconnectors.framework.api.ConnectorFacade;
import org.identityconnectors.framework.api.ConnectorFacadeFactory;
import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.AttributeUtil;
import org.identityconnectors.framework.common.objects.ConnectorObject;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.OperationOptions;
import org.identityconnectors.framework.common.objects.OperationOptionsBuilder;
import org.identityconnectors.framework.common.objects.filter.FilterBuilder;
import org.identityconnectors.test.common.TestHelpers;
import org.junit.After;
import org.junit.AfterClass;
import org.identityconnectors.framework.impl.api.APIConfigurationImpl;
import org.identityconnectors.framework.impl.api.local.JavaClassProperties;
import org.junit.Before;
import org.opends.server.config.ConfigException;
import org.opends.server.types.DirectoryEnvironmentConfig;
import org.opends.server.types.InitializationException;
import org.opends.server.util.EmbeddedUtils;

public abstract class LdapConnectorTestBase {

    // Cf. data.ldif and bigcompany.ldif.
    public static final int PORT = 2389;

    public static final int SSL_PORT = 2636;

    public static final String EXAMPLE_COM_DN = "dc=example,dc=com";

    public static final String ADMIN_DN = "uid=admin,dc=example,dc=com";

    public static final GuardedString ADMIN_PASSWORD = new GuardedString("password".toCharArray());

    public static final String ACME_DN = "o=Acme,dc=example,dc=com";

    public static final String ACME_O = "Acme";

    public static final String CZECH_REPUBLIC_DN = "c=Czech Republic,o=Acme,dc=example,dc=com";

    public static final String CZECH_REPUBLIC_C = "Czech Republic";

    public static final String ACME_USERS_DN = "ou=Users,o=Acme,dc=example,dc=com";
    
    public static final String ACME_GROUPS_DN = "ou=groups,o=Acme,dc=example,dc=com";

    public static final String BUGS_BUNNY_DN = "uid=bugs.bunny,ou=Users,o=Acme,dc=example,dc=com";

    public static final String BUGS_BUNNY_UID = "bugs.bunny";

    public static final String BBUNNY_UID = "bbunny";

    public static final String BUGS_BUNNY_CN = "Bugs Bunny";

    public static final String BUGS_BUNNY_SN = "Bunny";

    public static final String ELMER_FUDD_DN = "uid=elmer.fudd,ou=Users,o=Acme,dc=example,dc=com";

    public static final String ELMER_FUDD_UID = "elmer.fudd";

    public static final String SYLVESTER_DN = "uid=sylvester,ou=Users,o=Acme,dc=example,dc=com";

    public static final String SYLVESTER_UID = "sylvester";

    public static final String EXPIRED_UID = "expired";

    public static final String BUGS_AND_FRIENDS_DN = "cn=Bugs and Friends,o=Acme,dc=example,dc=com";

    public static final String EXTERNAL_PEERS_DN = "cn=External Peers,o=Acme,dc=example,dc=com";

    public static final String UNIQUE_BUGS_AND_FRIENDS_DN = "cn=Unique Bugs and Friends,o=Acme,dc=example,dc=com";

    public static final String UNIQUE_BUGS_AND_FRIENDS_CN = "Unique Bugs and Friends";

    public static final String UNIQUE_EXTERNAL_PEERS_DN = "cn=Unique External Peers,o=Acme,dc=example,dc=com";

    public static final String UNIQUE_EMPTY_GROUP_DN = "cn=Unique Empty Group,o=Acme,dc=example,dc=com";

    public static final String POSIX_BUGS_AND_FRIENDS_DN = "cn=POSIX Bugs and Friends,o=Acme,dc=example,dc=com";

    public static final String POSIX_EXTERNAL_PEERS_DN = "cn=POSIX External Peers,o=Acme,dc=example,dc=com";

    public static final String POSIX_EMPTY_GROUP_DN = "cn=POSIX Empty Group,o=Acme,dc=example,dc=com";

    public static final String POSIX_BUGS_BUNNY_GROUP = "cn=POSIX Bugs Bunny Group,o=Acme,dc=example,dc=com";

    public static final String SMALL_COMPANY_DN = "o=Small Company,dc=example,dc=com";

    public static final String SMALL_COMPANY_O = "Small Company";

    public static final String SINGLE_ACCOUNT_DN = "uid=single.account,o=Small Company,dc=example,dc=com";

    public static final String SINGLE_ACCOUNT_UID = "single.account";

    public static final String OWNER_DN = "cn=Owner,o=Small Company,dc=example,dc=com";

    public static final String BIG_COMPANY_DN = "o=Big Company,dc=example,dc=com";

    public static final String BIG_COMPANY_O = "Big Company";

    public static final String USER_0_DN = "uid=user.0,ou=People,o=Big Company,dc=example,dc=com";

    public static final String USER_0_UID = "user.0";

    public static final String USER_0_CN = "Aaccf Amar";

    public static final String USER_0_SN = "Amar";

    public static final String USER_0_GIVEN_NAME = "Aaccf";
    
    public static final String NAME_WITH_COMMA = "Pavan, Kumar";

    // Cf. test/opends/config/config.ldif and setup-test-opends.xml.
    private static final String[] FILES = {
        "config/config.ldif",
        "config/admin-backend.ldif",
        "config/keystore",
        "config/keystore.pin",
        "config/schema/00-core.ldif",
        "config/schema/01-pwpolicy.ldif",
        "config/schema/02-config.ldif",
        "config/schema/03-changelog.ldif",
        "config/schema/03-rfc2713.ldif",
        "config/schema/03-rfc2714.ldif",
        "config/schema/03-rfc2739.ldif",
        "config/schema/03-rfc2926.ldif",
        "config/schema/03-rfc3112.ldif",
        "config/schema/03-rfc3712.ldif",
        "config/schema/03-uddiv3.ldif",
        "config/schema/04-rfc2307bis.ldif",
        "db/userRoot/00000000.jdb"
    };

    @AfterClass
    public static void afterClass() {
        if (EmbeddedUtils.isRunning()) {
            stopServer();
        }
    }

    @Before
    public void before() throws Exception {
        if (!EmbeddedUtils.isRunning()) {
            startServer();
        }
    }

    @After
    public void after() throws Exception {
        if (restartServerAfterEachTest()) {
            stopServer();
        }
    }

    protected abstract boolean restartServerAfterEachTest();

    public static LdapConfiguration newConfiguration() {
        // IdM will not read the schema, so prefer to test with that setting.
        return newConfiguration(false);
    }

    public static LdapConfiguration newConfiguration(final boolean readSchema) {
        final LdapConfiguration config = new LdapConfiguration();
        // Cf. opends/config.ldif.
        config.setHost("localhost");
        config.setPort(PORT);
        config.setBaseContexts(ACME_DN, BIG_COMPANY_DN);
        config.setPrincipal(ADMIN_DN);
        config.setCredentials(ADMIN_PASSWORD);
        config.setReadSchema(readSchema);
        return config;
    }

    public static ConnectorFacade newFacade() {
        return newFacade(newConfiguration());
    }

    public static ConnectorFacade newFacade(final LdapConfiguration cfg) {
        final ConnectorFacadeFactory factory = ConnectorFacadeFactory.getInstance();
        final APIConfiguration impl = TestHelpers.createTestConfiguration(LdapConnector.class, cfg);
        // TODO: remove the line below when using ConnId >= 1.4.0.1
        ((APIConfigurationImpl) impl).
                setConfigurationProperties(JavaClassProperties.createConfigurationProperties(cfg));
        return factory.newInstance(impl);
    }

    public static ConnectorObject searchByAttribute(final ConnectorFacade facade,
            final ObjectClass oclass, final Attribute attr) {

        return searchByAttribute(facade, oclass, attr, (OperationOptions) null);
    }

    public static ConnectorObject searchByAttribute(final ConnectorFacade facade,
            final ObjectClass oclass, final Attribute attr, final String... attributesToGet) {

        final OperationOptionsBuilder builder = new OperationOptionsBuilder();
        builder.setAttributesToGet(attributesToGet);
        return searchByAttribute(facade, oclass, attr, builder.build());
    }

    public static ConnectorObject searchByAttribute(final ConnectorFacade facade,
            final ObjectClass oclass, final Attribute attr, final OperationOptions options) {

        final List<ConnectorObject> objects = TestHelpers.searchToList(facade, oclass,
                FilterBuilder.equalTo(attr), options);
        return objects.isEmpty() ? null : objects.get(0);
    }

    public static ConnectorObject findByAttribute(final List<ConnectorObject> objects,
            final String attrName, final Object value) {

        for (ConnectorObject object : objects) {
            final Attribute attr = object.getAttributeByName(attrName);
            if (attr != null) {
                final Object attrValue = AttributeUtil.getSingleValue(attr);
                if (value.equals(attrValue)) {
                    return object;
                }
            }
        }
        return null;
    }

    protected void startServer()
            throws IOException {

        final File root = new File(System.getProperty("java.io.tmpdir"), "opends");
        IOUtil.delete(root);
        if (!root.mkdirs()) {
            throw new IOException();
        }
        for (String path : FILES) {
            final File file = new File(root, path);
            final File parent = file.getParentFile();
            if (!parent.exists() && !parent.mkdirs()) {
                throw new IOException(file.getAbsolutePath());
            }
            IOUtil.extractResourceToFile(LdapConnectorTestBase.class, "opends/" + path, file);
        }

        final File configDir = new File(root, "config");
        final File configFile = new File(configDir, "config.ldif");
        final File schemaDir = new File(configDir, "schema");
        final File lockDir = new File(root, "locks");
        if (!lockDir.mkdirs()) {
            throw new IOException();
        }

        try {
            final DirectoryEnvironmentConfig config = new DirectoryEnvironmentConfig();
            config.setServerRoot(root);
            config.setConfigFile(configFile);
            config.setSchemaDirectory(schemaDir);
            config.setLockDirectory(lockDir);
            EmbeddedUtils.startServer(config);
        } catch (ConfigException e) {
            throw new IOException(e);
        } catch (InitializationException e) {
            throw new IOException(e);
        }
    }

    protected static void stopServer() {
        EmbeddedUtils.stopServer("org.test.opends.EmbeddedOpenDS", null);
        // It seems that EmbeddedUtils.stopServer() returns before the server
        // has stopped listening on its port,
        // causing the next test to fail when starting the server.
        final int WAIT = 200; // ms
        final int ITERATIONS = 25;
        for (int i = 1;; i++) {
            try {
                new Socket(InetAddress.getLocalHost(), PORT).close();
            } catch (IOException e) {
                // Okay, server has stopped.
                return;
            }
            if (i < ITERATIONS) {
                try {
                    Thread.sleep(WAIT);
                } catch (InterruptedException e) {
                }
            } else {
                break;
            }
        }
        fail("OpenDS failed to stop");
    }
}
