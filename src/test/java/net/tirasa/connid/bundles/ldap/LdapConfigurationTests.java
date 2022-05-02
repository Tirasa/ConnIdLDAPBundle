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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.util.Arrays;
import org.identityconnectors.common.CollectionUtil;
import org.identityconnectors.common.security.GuardedByteArray;
import org.identityconnectors.framework.common.exceptions.ConfigurationException;
import org.identityconnectors.test.common.TestHelpers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class LdapConfigurationTests {

    private static final String INVALID_DN = "dc=a,,";

    private LdapConfiguration config;

    @BeforeEach
    public void before() throws Exception {
        config = new LdapConfiguration();
        config.setConnectorMessages(TestHelpers.createDummyMessages());
        config.setHost("localhost");
        config.setBaseContexts("dc=example,dc=com");
        assertCanValidate(config);
    }

    @Test
    public void testBaseContextsNotEmpty() {
        config.setBaseContexts();
        assertThrows(ConfigurationException.class, () -> config.validate());
    }

    @Test
    public void testBaseContextsItemNotNull() {
        config.setBaseContexts((String) null);
        assertThrows(ConfigurationException.class, () -> config.validate());
    }

    @Test
    public void testBaseContextsItemNotBlank() {
        config.setBaseContexts(" ");
        assertThrows(ConfigurationException.class, () -> config.validate());
    }

    @Test
    public void testBaseContextsValid() {
        config.setBaseContexts(LdapConnectorTestBase.ACME_DN, INVALID_DN);
        assertThrows(ConfigurationException.class, () -> config.validate());
    }

    @Test
    public void testPasswordAttributeNotNull() {
        config.setPasswordAttribute(null);
        assertThrows(ConfigurationException.class, () -> config.validate());
    }

    @Test
    public void testPasswordAttributeNotBlank() {
        config.setPasswordAttribute(" ");
        assertThrows(ConfigurationException.class, () -> config.validate());
    }

    @Test
    public void testAccountObjectClassesNotEmpty() {
        config.setAccountObjectClasses();
        assertThrows(ConfigurationException.class, () -> config.validate());
    }

    @Test
    public void testAccountObjectClassesItemNotNull() {
        config.setAccountObjectClasses((String) null);
        assertThrows(ConfigurationException.class, () -> config.validate());
    }

    @Test
    public void testAccountUserNameAttributesNotEmpty() {
        config.setAccountUserNameAttributes();
        assertThrows(ConfigurationException.class, () -> config.validate());
    }

    @Test
    public void testAccountUserNameAttributesItemNotNull() {
        config.setAccountUserNameAttributes((String) null);
        assertThrows(ConfigurationException.class, () -> config.validate());
    }

    @Test
    public void testGroupMemberAttributeNotNull() {
        config.setGroupMemberAttribute(null);
        assertThrows(ConfigurationException.class, () -> config.validate());
    }

    @Test
    public void testGroupMemberAttributeNotBlank() {
        config.setGroupMemberAttribute(" ");
        assertThrows(ConfigurationException.class, () -> config.validate());
    }

    @Test
    public void testVlvSortAttributeNotNull() {
        config.setVlvSortAttribute(null);
        assertThrows(ConfigurationException.class, () -> config.validate());
    }

    @Test
    public void testVlvSortAttributeNotBlank() {
        config.setVlvSortAttribute(" ");
        assertThrows(ConfigurationException.class, () -> config.validate());
    }

    @Test
    public void testBaseContextsToSynchronizeItemNotNull() {
        config.setBaseContextsToSynchronize((String) null);
        assertThrows(ConfigurationException.class, () -> config.validate());
    }

    @Test
    public void testBaseContextsToSynchronizeItemNotBlank() {
        config.setBaseContextsToSynchronize(" ");
        assertThrows(ConfigurationException.class, () -> config.validate());
    }

    @Test
    public void testBaseContextsToSyncronizeValid() {
        config.setBaseContextsToSynchronize(LdapConnectorTestBase.ACME_DN, INVALID_DN);
        assertThrows(ConfigurationException.class, () -> config.validate());
    }

    @Test
    public void testObjectClassesToSynchronizeNotEmpty() {
        config.setObjectClassesToSynchronize();
        assertThrows(ConfigurationException.class, () -> config.validate());
    }

    @Test
    public void testObjectClassesToSynchronizeItemNotNull() {
        config.setObjectClassesToSynchronize((String) null);
        assertThrows(ConfigurationException.class, () -> config.validate());
    }

    @Test
    public void testObjectClassesToSynchronizeItemNotBlank() {
        config.setObjectClassesToSynchronize(" ");
        assertThrows(ConfigurationException.class, () -> config.validate());
    }

    @Test
    public void testAttributesToSynchronizeItemNotNull() {
        config.setAttributesToSynchronize((String) null);
        assertThrows(ConfigurationException.class, () -> config.validate());
    }

    @Test
    public void testAttributesToSynchronizeItemNotBlank() {
        config.setAttributesToSynchronize(" ");
        assertThrows(ConfigurationException.class, () -> config.validate());
    }

    @Test
    public void testModifiersNamesToFilterOutItemNotNull() {
        config.setModifiersNamesToFilterOut((String) null);
        assertThrows(ConfigurationException.class, () -> config.validate());
    }

    @Test
    public void testModifiersNamesToFilterOutItemNotBlank() {
        config.setModifiersNamesToFilterOut(" ");
        assertThrows(ConfigurationException.class, () -> config.validate());
    }

    @Test
    public void testModifiersNamesToFilterOutValid() {
        config.setModifiersNamesToFilterOut(LdapConnectorTestBase.ACME_DN, INVALID_DN);
        assertThrows(ConfigurationException.class, () -> config.validate());
    }

    @Test
    public void testChangeNumberAttributeNotNull() {
        config.setChangeNumberAttribute(null);
        assertThrows(ConfigurationException.class, () -> config.validate());
    }

    @Test
    public void testChangeNumberAttributeNotBlank() {
        config.setChangeNumberAttribute(" ");
        assertThrows(ConfigurationException.class, () -> config.validate());
    }

    @Test
    public void testChangeLogBlockSizeGreatherThanZero() {
        config.setChangeLogBlockSize(0);
        assertThrows(ConfigurationException.class, () -> config.validate());
    }

    @Test
    public void testPasswordAttributeToSynchronizeNotNull() {
        config.setSynchronizePasswords(true);
        config.setPasswordAttributeToSynchronize(null);
        assertThrows(ConfigurationException.class, () -> config.validate());
    }

    @Test
    public void testPasswordAttributeToSynchronizeNotBlank() {
        config.setSynchronizePasswords(true);
        config.setPasswordAttributeToSynchronize(" ");
        assertThrows(ConfigurationException.class, () -> config.validate());
    }

    @Test
    public void testPasswordDecryptionKeyNotNull() {
        config.setSynchronizePasswords(true);
        config.setPasswordAttributeToSynchronize("somepassword");
        config.setPasswordDecryptionKey(null);
        config.setPasswordDecryptionInitializationVector(new GuardedByteArray(new byte[1]));
        assertThrows(ConfigurationException.class, () -> config.validate());
    }

    @Test
    public void testPasswordDecryptionKeyNotBlank() {
        config.setSynchronizePasswords(true);
        config.setPasswordAttributeToSynchronize("somepassword");
        config.setPasswordDecryptionKey(new GuardedByteArray(new byte[0]));
        config.setPasswordDecryptionInitializationVector(new GuardedByteArray(new byte[1]));
        assertThrows(ConfigurationException.class, () -> config.validate());
    }

    @Test
    public void testPasswordDecryptionInitializationVectorNotNull() {
        config.setSynchronizePasswords(true);
        config.setPasswordAttributeToSynchronize("somepassword");
        config.setPasswordDecryptionKey(new GuardedByteArray(new byte[1]));
        config.setPasswordDecryptionInitializationVector(null);
        assertThrows(ConfigurationException.class, () -> config.validate());
    }

    @Test
    public void testPasswordDecryptionInitializationVectorNotBlank() {
        config.setSynchronizePasswords(true);
        config.setPasswordAttributeToSynchronize("somepassword");
        config.setPasswordDecryptionKey(new GuardedByteArray(new byte[1]));
        config.setPasswordDecryptionInitializationVector(new GuardedByteArray(new byte[0]));
        assertThrows(ConfigurationException.class, () -> config.validate());
    }

    @Test
    public void testDefaultValues() {
        config = new LdapConfiguration();
        assertNull(config.getHost());
        assertEquals(LdapConfiguration.DEFAULT_PORT, config.getPort());
        assertFalse(config.isSsl());
        assertEquals(0, config.getFailover().length);
        assertNull(config.getPrincipal());
        assertNull(config.getCredentials());
        assertEquals(0, config.getBaseContexts().length);
        assertEquals("userPassword", config.getPasswordAttribute());
        assertEquals(CollectionUtil.newList("top", "person", "organizationalPerson", "inetOrgPerson"),
                Arrays.asList(config.getAccountObjectClasses()));
        assertEquals(CollectionUtil.newList("uid", "cn"), Arrays.asList(config.getAccountUserNameAttributes()));
        assertNull(config.getAccountSearchFilter());
        assertEquals("uniqueMember", config.getGroupMemberAttribute());
        assertFalse(config.isMaintainLdapGroupMembership());
        assertFalse(config.isMaintainPosixGroupMembership());
        assertFalse(config.isRespectResourcePasswordPolicyChangeAfterReset());
        assertNull(config.getPasswordHashAlgorithm());
        assertFalse(config.isUseVlvControls());
        assertEquals("uid", config.getVlvSortAttribute());
        assertEquals("entryUUID", config.getUidAttribute());
        assertTrue(config.isReadSchema());
        assertEquals(0, config.getBaseContextsToSynchronize().length);
        assertTrue(Arrays.equals(new String[] { "inetOrgPerson" }, config.getObjectClassesToSynchronize()));
        assertEquals(0, config.getAttributesToSynchronize().length);
        assertEquals(0, config.getModifiersNamesToFilterOut().length);
        assertNull(config.getAccountSynchronizationFilter());
        assertEquals(100, config.getChangeLogBlockSize());
        assertEquals("changeNumber", config.getChangeNumberAttribute());
        assertFalse(config.isFilterWithOrInsteadOfAnd());
        assertTrue(config.isRemoveLogEntryObjectClassFromFilter());
        assertFalse(config.isSynchronizePasswords());
        assertNull(config.getPasswordAttributeToSynchronize());
        assertNull(config.getPasswordDecryptionKey());
        assertNull(config.getPasswordDecryptionInitializationVector());
        assertNull(config.getGroupSearchFilter());
        assertEquals(0, config.getReadTimeout());
        assertEquals(0, config.getConnectTimeout());
    }

    private static void assertCanValidate(LdapConfiguration config) {
        try {
            config.validate();
        } catch (Exception e) {
            fail();
        }
    }
}
