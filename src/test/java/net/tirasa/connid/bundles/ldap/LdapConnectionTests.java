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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import com.sun.jndi.ldap.ctl.PagedResultsControl;
import com.sun.jndi.ldap.ctl.VirtualListViewControl;
import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import net.tirasa.connid.bundles.ldap.commons.LdapUtil;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import net.tirasa.connid.bundles.ldap.LdapConnection.ServerType;
import org.junit.jupiter.api.Test;

public class LdapConnectionTests extends LdapConnectorTestBase {

    @Test
    public void sSL() throws NamingException {
        BlindTrustProvider.register();
        LdapConfiguration config = newConfiguration();
        config.setSsl(true);
        config.setPort(SSL_PORT);
        checkConnection(config);
    }

    @Test
    public void testStartTLS() throws NamingException {
        BlindTrustProvider.register();
        LdapConfiguration config = newConfiguration();
        config.setStartTLSEnabled(true);
        checkConnection(config);
    }
    
    @Test
    public void failover() throws NamingException {
        LdapConfiguration config = newConfiguration();
        config.setHost("foobarbaz");
        config.setPort(65535);
        try {
            checkConnection(config);
        } catch (ConnectorException e) {
            // OK.
        } catch (NamingException e) {
            // Should not normally occur.
            throw e;
        }

        config = newConfiguration();
        config.setHost("foobarbaz");
        config.setPort(65535);
        config.setFailover("ldap://localhost:" + PORT);
        checkConnection(config);
    }

    private void checkConnection(LdapConfiguration config) throws NamingException {
        LdapConnection conn = new LdapConnection(config);
        Attributes attrs = conn.getInitialContext().getAttributes(BUGS_BUNNY_DN);
        assertEquals(BUGS_BUNNY_CN, LdapUtil.getStringAttrValue(attrs, "cn"));
    }

    @Test
    public void defaultAuthenticationMethodIsInferred() throws NamingException {
        LdapConfiguration config = newConfiguration();
        config.setPrincipal(null);
        LdapConnection conn = new LdapConnection(config);
        assertEquals("none", conn.getInitialContext().getEnvironment().get(Context.SECURITY_AUTHENTICATION));

        config = newConfiguration();
        config.setPrincipal(ADMIN_DN);
        config.setCredentials(ADMIN_PASSWORD);
        conn = new LdapConnection(config);
        assertEquals("simple", conn.getInitialContext().getEnvironment().get(Context.SECURITY_AUTHENTICATION));
    }

    @Test
    public void test() {
        LdapConfiguration config = newConfiguration();
        config.setPort(4242);
        LdapConnection conn = new LdapConnection(config);
        try {
            conn.test();
            fail();
        } catch (RuntimeException e) {
            // Expected.
        }

        config = newConfiguration();
        config.setHost("invalid");
        conn = new LdapConnection(config);
        try {
            conn.test();
            fail();
        } catch (RuntimeException e) {
            // Expected.
        }

        config = newConfiguration();
        config.setPrincipal("uid=nobody");
        conn = new LdapConnection(config);
        try {
            conn.test();
            fail();
        } catch (RuntimeException e) {
            // Expected.
        }

        config = newConfiguration();
        config.setCredentials(new GuardedString("bogus".toCharArray()));
        conn = new LdapConnection(config);
        try {
            conn.test();
            fail();
        } catch (RuntimeException e) {
            // Expected.
        }

        config = newConfiguration();
        conn = new LdapConnection(config);
        conn.test();
    }

    @Test
    public void checkAlive() throws Exception {
        // Set readSchema to true since we are calling createNativeSchema() below, and we
        // want to get the server schema, not the static one.
        LdapConfiguration config = newConfiguration(true);
        LdapConnection conn = new LdapConnection(config);
        conn.checkAlive();
        // Ensure the connection is really connected to the server.
        conn.createNativeSchema();
        conn.checkAlive();
    }

    @Test
    public void supportedControls() {
        LdapConnection conn = new LdapConnection(newConfiguration());
        assertTrue(conn.supportsControl(PagedResultsControl.OID));
        assertTrue(conn.supportsControl(VirtualListViewControl.OID));
    }

    @Test
    public void serverType() {
        LdapConnection conn = new LdapConnection(newConfiguration());
        assertEquals(ServerType.OPENDJ, conn.getServerType());
    }
}
