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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.fail;

import net.tirasa.connid.bundles.ldap.commons.LdapConstants;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.api.ConnectorFacade;
import org.identityconnectors.framework.common.exceptions.ConnectorSecurityException;
import org.identityconnectors.framework.common.exceptions.PasswordExpiredException;
import org.identityconnectors.framework.common.objects.ConnectorObject;
import org.identityconnectors.framework.common.objects.Name;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.OperationOptions;
import org.identityconnectors.framework.common.objects.OperationOptionsBuilder;
import org.identityconnectors.framework.common.objects.Uid;
import org.junit.jupiter.api.Test;

public class LdapAuthenticateTests extends LdapConnectorTestBase {

    @Test
    public void authenticateWithDefaultConfiguration() {
        ConnectorFacade facade = newFacade();
        ConnectorObject bugs = searchByAttribute(facade, ObjectClass.ACCOUNT, new Name(BUGS_BUNNY_DN));
        Uid uid = facade.authenticate(ObjectClass.ACCOUNT, BUGS_BUNNY_CN,
                new GuardedString("carrot".toCharArray()), null);
        assertEquals(bugs.getUid(), uid);
        uid = facade.resolveUsername(ObjectClass.ACCOUNT, BUGS_BUNNY_CN, null);
        assertEquals(bugs.getUid(), uid);

        uid = facade.authenticate(ObjectClass.ACCOUNT, BUGS_BUNNY_UID,
                new GuardedString("carrot".toCharArray()),
                null);
        assertEquals(bugs.getUid(), uid);
        uid = facade.resolveUsername(ObjectClass.ACCOUNT, BUGS_BUNNY_UID, null);
        assertEquals(bugs.getUid(), uid);
    }

    @Test
    public void authenticateWithCustomAttributes() {
        ConnectorFacade facade = newFacade();
        ConnectorObject bugs = searchByAttribute(facade, ObjectClass.ACCOUNT, new Name(BUGS_BUNNY_DN));
        OperationOptionsBuilder builder = new OperationOptionsBuilder();
        builder.setOption(LdapConstants.LDAP_UID_ATTRS_NAME, new String[] { "sn" });
        OperationOptions options = builder.build();
        Uid uid = facade.authenticate(ObjectClass.ACCOUNT, BUGS_BUNNY_SN,
                new GuardedString("carrot".toCharArray()),
                options);
        assertEquals(bugs.getUid(), uid);
        uid = facade.resolveUsername(ObjectClass.ACCOUNT, BUGS_BUNNY_SN, options);
        assertEquals(bugs.getUid(), uid);

        // Should not be possible to authenticate with the attributes from the 
        // default configuration ("cn"...
        try {
            facade.authenticate(ObjectClass.ACCOUNT, BUGS_BUNNY_CN,
                    new GuardedString("carrot".toCharArray()),
                    options);
            fail();
        } catch (ConnectorSecurityException e) {
        }
        try {
            facade.resolveUsername(ObjectClass.ACCOUNT, BUGS_BUNNY_CN, options);
            fail();
        } catch (ConnectorSecurityException e) {
        }

        // ... and "uid").
        try {
            facade.authenticate(ObjectClass.ACCOUNT, BUGS_BUNNY_UID,
                    new GuardedString("carrot".toCharArray()),
                    options);
            fail();
        } catch (ConnectorSecurityException e) {
        }
        try {
            facade.resolveUsername(ObjectClass.ACCOUNT, BUGS_BUNNY_UID,
                    options);
            fail();
        } catch (ConnectorSecurityException e) {
        }
    }

    @Test
    public void authenticateWithEntryDN() {
        LdapConfiguration config = newConfiguration();
        config.setAccountUserNameAttributes("entryDN");
        ConnectorFacade facade = newFacade(config);
        ConnectorObject bugs = searchByAttribute(facade, ObjectClass.ACCOUNT, new Name(BUGS_BUNNY_DN));
        Uid uid = facade.authenticate(ObjectClass.ACCOUNT, BUGS_BUNNY_DN,
                new GuardedString("carrot".toCharArray()),
                null);
        assertEquals(bugs.getUid(), uid);
        uid = facade.resolveUsername(ObjectClass.ACCOUNT, BUGS_BUNNY_DN, null);
        assertEquals(bugs.getUid(), uid);
    }

    @Test
    public void authenticateInvalidPassword() {
        ConnectorFacade facade = newFacade();
        assertThrows(
                ConnectorSecurityException.class,
                () -> facade.authenticate(
                        ObjectClass.ACCOUNT, BUGS_BUNNY_CN, new GuardedString("rabbithole".toCharArray()), null));
    }

    @Test
    public void authenticateUnknownAccount() {
        ConnectorFacade facade = newFacade();
        try {
            facade.authenticate(ObjectClass.ACCOUNT,
                    "hopefully.inexisting.user",
                    new GuardedString("none".toCharArray()), null);
            fail();
        } catch (ConnectorSecurityException e) {
        }
        try {
            facade.resolveUsername(ObjectClass.ACCOUNT,
                    "hopefully.inexisting.user", null);
            fail();
        } catch (ConnectorSecurityException e) {
        }
    }

    @Test
    public void authenticateExpiredPassword() {
        LdapConfiguration config = newConfiguration();
        config.setRespectResourcePasswordPolicyChangeAfterReset(false);
        ConnectorFacade facade = newFacade(config);
        facade.authenticate(ObjectClass.ACCOUNT, EXPIRED_UID,
                new GuardedString("password".toCharArray()),
                null);

        config = newConfiguration();
        config.setRespectResourcePasswordPolicyChangeAfterReset(true);
        facade = newFacade(config);
        try {
            facade.authenticate(ObjectClass.ACCOUNT, EXPIRED_UID,
                    new GuardedString("password".toCharArray()),
                    null);
            fail();
        } catch (PasswordExpiredException e) {
            // OK.
        }
    }
}
