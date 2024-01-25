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

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
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
import org.identityconnectors.framework.common.objects.OperationOptions;
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
    public void baseContextsNotEmpty() {
        config.setBaseContexts();
        assertThrows(ConfigurationException.class, () -> config.validate());
    }

    @Test
    public void baseContextsItemNotNull() {
        config.setBaseContexts((String) null);
        assertThrows(ConfigurationException.class, () -> config.validate());
    }

    @Test
    public void baseContextsItemNotBlank() {
        config.setBaseContexts(" ");
        assertThrows(ConfigurationException.class, () -> config.validate());
    }

    @Test
    public void baseContextsValid() {
        config.setBaseContexts(LdapConnectorTestBase.ACME_DN, INVALID_DN);
        assertThrows(ConfigurationException.class, () -> config.validate());
    }

    @Test
    public void passwordAttributeNotNull() {
        config.setPasswordAttribute(null);
        assertThrows(ConfigurationException.class, () -> config.validate());
    }

    @Test
    public void passwordAttributeNotBlank() {
        config.setPasswordAttribute(" ");
        assertThrows(ConfigurationException.class, () -> config.validate());
    }

    @Test
    public void accountObjectClassesNotEmpty() {
        config.setAccountObjectClasses();
        assertThrows(ConfigurationException.class, () -> config.validate());
    }

    @Test
    public void accountObjectClassesItemNotNull() {
        config.setAccountObjectClasses((String) null);
        assertThrows(ConfigurationException.class, () -> config.validate());
    }

    @Test
    public void accountUserNameAttributesNotEmpty() {
        config.setAccountUserNameAttributes();
        assertThrows(ConfigurationException.class, () -> config.validate());
    }

    @Test
    public void accountUserNameAttributesItemNotNull() {
        config.setAccountUserNameAttributes((String) null);
        assertThrows(ConfigurationException.class, () -> config.validate());
    }

    @Test
    public void anyObjectNameAttributesNotEmpty() {
        config.setAnyObjectNameAttributes();
        assertThrows(ConfigurationException.class, () -> config.validate());
    }

    @Test
    public void anyObjectNameAttributesNotNull() {
        config.setAnyObjectNameAttributes((String) null);
        assertThrows(ConfigurationException.class, () -> config.validate());
    }

    @Test
    public void anyObjectNameAttributesNotBlank() {
        config.setAnyObjectNameAttributes(" ");
        assertThrows(ConfigurationException.class, () -> config.validate());
    }

    @Test
    public void anyObjectClassesNotEmpty() {
        config.setAnyObjectClasses();
        assertThrows(ConfigurationException.class, () -> config.validate());
    }

    @Test
    public void anyObjectClassesNotNull() {
        config.setAnyObjectClasses((String) null);
        assertThrows(ConfigurationException.class, () -> config.validate());
    }

    @Test
    public void anyObjectClassesNotBlank() {
        config.setAnyObjectClasses(" ");
        assertThrows(ConfigurationException.class, () -> config.validate());
    }

    @Test
    public void groupMemberAttributeNotNull() {
        config.setGroupMemberAttribute(null);
        assertThrows(ConfigurationException.class, () -> config.validate());
    }

    @Test
    public void groupMemberAttributeNotBlank() {
        config.setGroupMemberAttribute(" ");
        assertThrows(ConfigurationException.class, () -> config.validate());
    }

    @Test
    public void vlvSortAttributeNotNull() {
        config.setVlvSortAttribute(null);
        assertThrows(ConfigurationException.class, () -> config.validate());
    }

    @Test
    public void vlvSortAttributeNotBlank() {
        config.setVlvSortAttribute(" ");
        assertThrows(ConfigurationException.class, () -> config.validate());
    }

    @Test
    public void baseContextsToSynchronizeItemNotNull() {
        config.setBaseContextsToSynchronize((String) null);
        assertThrows(ConfigurationException.class, () -> config.validate());
    }

    @Test
    public void baseContextsToSynchronizeItemNotBlank() {
        config.setBaseContextsToSynchronize(" ");
        assertThrows(ConfigurationException.class, () -> config.validate());
    }

    @Test
    public void baseContextsToSyncronizeValid() {
        config.setBaseContextsToSynchronize(LdapConnectorTestBase.ACME_DN, INVALID_DN);
        assertThrows(ConfigurationException.class, () -> config.validate());
    }

    @Test
    public void objectClassesToSynchronizeNotEmpty() {
        config.setObjectClassesToSynchronize();
        assertThrows(ConfigurationException.class, () -> config.validate());
    }

    @Test
    public void objectClassesToSynchronizeItemNotNull() {
        config.setObjectClassesToSynchronize((String) null);
        assertThrows(ConfigurationException.class, () -> config.validate());
    }

    @Test
    public void objectClassesToSynchronizeItemNotBlank() {
        config.setObjectClassesToSynchronize(" ");
        assertThrows(ConfigurationException.class, () -> config.validate());
    }

    @Test
    public void attributesToSynchronizeItemNotNull() {
        config.setAttributesToSynchronize((String) null);
        assertThrows(ConfigurationException.class, () -> config.validate());
    }

    @Test
    public void attributesToSynchronizeItemNotBlank() {
        config.setAttributesToSynchronize(" ");
        assertThrows(ConfigurationException.class, () -> config.validate());
    }

    @Test
    public void modifiersNamesToFilterOutItemNotNull() {
        config.setModifiersNamesToFilterOut((String) null);
        assertThrows(ConfigurationException.class, () -> config.validate());
    }

    @Test
    public void modifiersNamesToFilterOutItemNotBlank() {
        config.setModifiersNamesToFilterOut(" ");
        assertThrows(ConfigurationException.class, () -> config.validate());
    }

    @Test
    public void modifiersNamesToFilterOutValid() {
        config.setModifiersNamesToFilterOut(LdapConnectorTestBase.ACME_DN, INVALID_DN);
        assertThrows(ConfigurationException.class, () -> config.validate());
    }

    @Test
    public void changeNumberAttributeNotNull() {
        config.setChangeNumberAttribute(null);
        assertThrows(ConfigurationException.class, () -> config.validate());
    }

    @Test
    public void changeNumberAttributeNotBlank() {
        config.setChangeNumberAttribute(" ");
        assertThrows(ConfigurationException.class, () -> config.validate());
    }

    @Test
    public void changeLogBlockSizeGreatherThanZero() {
        config.setChangeLogBlockSize(0);
        assertThrows(ConfigurationException.class, () -> config.validate());
    }

    @Test
    public void passwordAttributeToSynchronizeNotNull() {
        config.setSynchronizePasswords(true);
        config.setPasswordAttributeToSynchronize(null);
        assertThrows(ConfigurationException.class, () -> config.validate());
    }

    @Test
    public void passwordAttributeToSynchronizeNotBlank() {
        config.setSynchronizePasswords(true);
        config.setPasswordAttributeToSynchronize(" ");
        assertThrows(ConfigurationException.class, () -> config.validate());
    }

    @Test
    public void passwordDecryptionKeyNotNull() {
        config.setSynchronizePasswords(true);
        config.setPasswordAttributeToSynchronize("somepassword");
        config.setPasswordDecryptionKey(null);
        config.setPasswordDecryptionInitializationVector(new GuardedByteArray(new byte[1]));
        assertThrows(ConfigurationException.class, () -> config.validate());
    }

    @Test
    public void passwordDecryptionKeyNotBlank() {
        config.setSynchronizePasswords(true);
        config.setPasswordAttributeToSynchronize("somepassword");
        config.setPasswordDecryptionKey(new GuardedByteArray(new byte[0]));
        config.setPasswordDecryptionInitializationVector(new GuardedByteArray(new byte[1]));
        assertThrows(ConfigurationException.class, () -> config.validate());
    }

    @Test
    public void passwordDecryptionInitializationVectorNotNull() {
        config.setSynchronizePasswords(true);
        config.setPasswordAttributeToSynchronize("somepassword");
        config.setPasswordDecryptionKey(new GuardedByteArray(new byte[1]));
        config.setPasswordDecryptionInitializationVector(null);
        assertThrows(ConfigurationException.class, () -> config.validate());
    }

    @Test
    public void passwordDecryptionInitializationVectorNotBlank() {
        config.setSynchronizePasswords(true);
        config.setPasswordAttributeToSynchronize("somepassword");
        config.setPasswordDecryptionKey(new GuardedByteArray(new byte[1]));
        config.setPasswordDecryptionInitializationVector(new GuardedByteArray(new byte[0]));
        assertThrows(ConfigurationException.class, () -> config.validate());
    }

    @Test
    public void defaultValues() {
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
        assertEquals("entryUUID", config.getGidAttribute());
        assertEquals("entryUUID", config.getAoidAttribute());
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
        assertEquals(CollectionUtil.newList("top"), Arrays.asList(config.getAnyObjectClasses()));
        assertEquals(CollectionUtil.newList("entryUUID"), Arrays.asList(config.getAnyObjectNameAttributes()));
        assertEquals(OperationOptions.SCOPE_SUBTREE, config.getUserSearchScope());
        assertEquals(OperationOptions.SCOPE_SUBTREE, config.getGroupSearchScope());
        assertEquals(OperationOptions.SCOPE_SUBTREE, config.getAnyObjectSearchScope());
        assertNull(config.getAnyObjectSearchFilter());
        assertEquals("net.tirasa.connid.bundles.ldap.sync.sunds.SunDSChangeLogSyncStrategy", config.getSyncStrategy());
    }

    @Test
    public void userSearchScopeNotNull() {
        assertThrows(NullPointerException.class, () -> config.setUserSearchScope((String) null));
    }

    @Test
    public void userSearchScopeNotBlank() {
        assertThrows(IllegalArgumentException.class, () -> config.setUserSearchScope(" "));
    }

    @Test
    public void userSearchScopeInvalid() {
        assertThrows(IllegalArgumentException.class, () -> config.setUserSearchScope("abc"));
    }

    @Test
    public void userSearchScopeValid() {
        assertDoesNotThrow(() -> config.setUserSearchScope("object"));
        assertDoesNotThrow(() -> config.setUserSearchScope("onelevel"));
        assertDoesNotThrow(() -> config.setUserSearchScope("subtree"));
    }

    @Test
    public void groupSearchScopeNotNull() {
        assertThrows(NullPointerException.class, () -> config.setGroupSearchScope((String) null));
    }

    @Test
    public void groupSearchScopeNotBlank() {
        assertThrows(IllegalArgumentException.class, () -> config.setGroupSearchScope(" "));
    }

    @Test
    public void groupSearchScopeInvalid() {
        assertThrows(IllegalArgumentException.class, () -> config.setGroupSearchScope("abc"));
    }

    @Test
    public void groupSearchScopeValid() {
        assertDoesNotThrow(() -> config.setGroupSearchScope("object"));
        assertDoesNotThrow(() -> config.setGroupSearchScope("onelevel"));
        assertDoesNotThrow(() -> config.setGroupSearchScope("subtree"));
    }

    @Test
    public void anyObjectSearchScopeNotNull() {
        assertThrows(NullPointerException.class, () -> config.setAnyObjectSearchScope((String) null));
    }

    @Test
    public void anyObjectSearchScopeNotBlank() {
        assertThrows(IllegalArgumentException.class, () -> config.setAnyObjectSearchScope(" "));
    }

    @Test
    public void anyObjectSearchScopeInvalid() {
        assertThrows(IllegalArgumentException.class, () -> config.setAnyObjectSearchScope("abc"));
    }

    @Test
    public void anyObjectSearchScopeValid() {
        assertDoesNotThrow(() -> config.setAnyObjectSearchScope("object"));
        assertDoesNotThrow(() -> config.setAnyObjectSearchScope("onelevel"));
        assertDoesNotThrow(() -> config.setAnyObjectSearchScope("subtree"));
    }

    @Test
    public void syncStrategyNotNull() {
        config.setSyncStrategy((String) null);
        assertThrows(ConfigurationException.class, () -> config.validate());
    }

    @Test
    public void syncStrategyNotBlank() {
        config.setSyncStrategy("");
        assertThrows(ConfigurationException.class, () -> config.validate());
    }

    @Test
    public void syncStrategyClassDoesNotExist() {
        config.setSyncStrategy("net.tirasa.connid.bundles.ldap.sync.LdapSyncStrategyThatDoesNotExist");
        assertThrows(ConfigurationException.class, () -> config.validate());
    }

    @Test
    public void syncStrategyClassIsNotSyncStrategy() {
        config.setSyncStrategy("net.tirasa.connid.bundles.ldap.modify.LdapCreate");
        assertThrows(ConfigurationException.class, () -> config.validate());
    }

    @Test
    public void syncStrategyClassIsNotInterface() {
        config.setSyncStrategy("net.tirasa.connid.bundles.ldap.sync.LdapSyncStrategy");
        assertThrows(ConfigurationException.class, () -> config.validate());
    }

    @Test
    public void syncStrategyValid() {
        config.setSyncStrategy("net.tirasa.connid.bundles.ldap.sync.sunds.SunDSChangeLogSyncStrategy");
        assertDoesNotThrow(() -> config.validate());
    }

    private static void assertCanValidate(LdapConfiguration config) {
        try {
            config.validate();
        } catch (Exception e) {
            fail();
        }
    }
}
