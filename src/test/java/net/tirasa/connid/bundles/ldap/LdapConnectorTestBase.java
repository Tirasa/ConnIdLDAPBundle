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

import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.ServerSocket;
import java.util.List;
import java.util.Properties;
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
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;

public abstract class LdapConnectorTestBase {

    public static String HOST;

    public static Integer PORT;

    public static Integer SSL_PORT;

    public static String TOOL_START_DS;

    public static String TOOL_STOP_DS;

    public static String TOOL_RESTORE;

    public static String BACKUP_DIR;

    public static final String EXAMPLE_COM_DN = "dc=example,dc=com";

    public static final String ADMIN_DN = "uid=admin,dc=example,dc=com";

    public static final GuardedString ADMIN_PASSWORD = new GuardedString("password".toCharArray());

    public static final String ACME_DN = "o=Acme,dc=example,dc=com";

    public static final String ACME_O = "Acme";

    public static final String CZECH_REPUBLIC_DN = "c=CZ,o=Acme,dc=example,dc=com";

    public static final String CZECH_REPUBLIC_C = "CZ";

    public static final String ACME_USERS_DN = "ou=Users,o=Acme,dc=example,dc=com";

    public static final String BUGS_BUNNY_DN = "uid=bugs.bunny,ou=Users,o=Acme,dc=example,dc=com";

    public static final String RENAME_ONE_TEST_DN = "uid=rename.one,ou=Users,o=Acme,dc=example,dc=com";

    public static final String RENAME_TWO_TEST_DN = "uid=rename.two,ou=Users,o=Acme,dc=example,dc=com";

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

    @BeforeAll
    public static void init() throws IOException {
        InputStream propStream = null;
        String setupDir = null;
        try {
            Properties props = new Properties();
            propStream = LdapConnectorTestBase.class.getResourceAsStream("/test.properties");
            props.load(propStream);

            HOST = props.getProperty("opendj.host");
            PORT = Integer.valueOf(props.getProperty("opendj.port"));
            SSL_PORT = Integer.valueOf(props.getProperty("opendj.sslport"));
            setupDir = props.getProperty("opendj.setup.dir");
            BACKUP_DIR = props.getProperty("opendj.backup.dir");
        } finally {
            IOUtil.quietClose(propStream);
        }

        assertNotNull(setupDir);
        TOOL_START_DS = setupDir + File.separator + "bin" + File.separator + "start-ds";
        TOOL_STOP_DS = setupDir + File.separator + "bin" + File.separator + "stop-ds";
        TOOL_RESTORE = setupDir + File.separator + "bin" + File.separator + "restore";
        if (System.getProperty("os.name").startsWith("Windows")) {
            TOOL_START_DS += ".bat";
            TOOL_STOP_DS += ".bat";
            TOOL_RESTORE += ".bat";
        }

        assertNotNull(HOST);
        assertNotNull(PORT);
        assertNotNull(SSL_PORT);
        assertNotNull(TOOL_START_DS);
        assertNotNull(TOOL_STOP_DS);
        assertNotNull(TOOL_RESTORE);
        assertNotNull(BACKUP_DIR);
    }

    private static boolean isOpenDJRunning() {
        boolean result;
        try {
            ServerSocket socket = new ServerSocket(PORT);
            socket.close();

            result = false;
        } catch (IOException e) {
            result = true;
        }
        return result;
    }

    @AfterAll
    public static void afterClass() throws Exception {
        if (isOpenDJRunning()) {
            stopServer();
        }
    }

    @BeforeEach
    public void before() throws Exception {
        if (!isOpenDJRunning()) {
            startServer();
        }
    }

    @AfterEach
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
        LdapConfiguration config = new LdapConfiguration();
        config.setHost(HOST);
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
        ConnectorFacadeFactory factory = ConnectorFacadeFactory.getInstance();
        APIConfiguration impl = TestHelpers.createTestConfiguration(LdapConnector.class, cfg);
        impl.getResultsHandlerConfiguration().setFilteredResultsHandlerInValidationMode(true);
        return factory.newInstance(impl);
    }

    public static ConnectorObject searchByAttribute(final ConnectorFacade facade,
            final ObjectClass oclass, final Attribute attr) {

        return searchByAttribute(facade, oclass, attr, (OperationOptions) null);
    }

    public static ConnectorObject searchByAttribute(final ConnectorFacade facade,
            final ObjectClass oclass, final Attribute attr, final String... attributesToGet) {

        return searchByAttribute(
                facade, oclass, attr, new OperationOptionsBuilder().setAttributesToGet(attributesToGet).build());
    }

    public static ConnectorObject searchByAttribute(final ConnectorFacade facade,
            final ObjectClass oclass, final Attribute attr, final OperationOptions options) {

        List<ConnectorObject> objects = TestHelpers.searchToList(facade, oclass,
                FilterBuilder.equalTo(attr), options);
        return objects.isEmpty() ? null : objects.get(0);
    }

    public static ConnectorObject findByAttribute(final List<ConnectorObject> objects,
            final String attrName, final Object value) {

        for (ConnectorObject object : objects) {
            Attribute attr = object.getAttributeByName(attrName);
            if (attr != null) {
                Object attrValue = AttributeUtil.getSingleValue(attr);
                if (value.equals(attrValue)) {
                    return object;
                }
            }
        }
        return null;
    }

    protected void startServer() throws IOException, InterruptedException {
        Process process = Runtime.getRuntime().exec(TOOL_START_DS);
        process.waitFor();
    }

    protected static void stopServer() throws IOException, InterruptedException {
        Process process = Runtime.getRuntime().exec(TOOL_STOP_DS);
        process.waitFor();

        process = Runtime.getRuntime().exec(TOOL_RESTORE + " -d " + BACKUP_DIR + File.separator + "userRoot");
        process.waitFor();
    }
}
