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
package net.tirasa.connid.bundles.ldap.schema;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.EnumSet;
import java.util.Set;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

import org.identityconnectors.framework.api.operations.AuthenticationApiOp;
import org.identityconnectors.framework.api.operations.SyncApiOp;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.identityconnectors.framework.common.objects.AttributeInfo;
import org.identityconnectors.framework.common.objects.AttributeInfoBuilder;
import org.identityconnectors.framework.common.objects.AttributeInfoUtil;
import org.identityconnectors.framework.common.objects.Name;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.ObjectClassInfo;
import org.identityconnectors.framework.common.objects.OperationalAttributes;
import org.identityconnectors.framework.common.objects.Schema;
import org.identityconnectors.framework.common.objects.AttributeInfo.Flags;

import net.tirasa.connid.bundles.ldap.LdapConfiguration;
import net.tirasa.connid.bundles.ldap.LdapConnection;
import net.tirasa.connid.bundles.ldap.LdapConnectorTestBase;
import net.tirasa.connid.bundles.ldap.commons.LdapConstants;
import net.tirasa.connid.bundles.ldap.LdapConnection.ServerType;

import org.junit.Test;

public class LdapSchemaMappingTests extends LdapConnectorTestBase {

    // TODO operational attributes.
    // TODO test for operation option infos.
    @Override
    protected boolean restartServerAfterEachTest() {
        return false;
    }

    @Test
    public void testObjectClassAttrIsReadOnly() {
        LdapConfiguration config = newConfiguration(true);
        Schema schema = newFacade(config).schema();
        for (ObjectClassInfo oci : schema.getObjectClassInfo()) {
            AttributeInfo attrInfo = AttributeInfoUtil.find("objectClass", oci.getAttributeInfo());
            assertFalse(attrInfo.isRequired());
            assertFalse(attrInfo.isCreateable());
            assertFalse(attrInfo.isUpdateable());
        }
    }

    @Test
    public void testAccountSchema() {
        LdapConfiguration config = newConfiguration(true);
        Schema schema = newFacade(config).schema();

        ObjectClassInfo oci = schema.findObjectClassInfo(ObjectClass.ACCOUNT_NAME);
        assertFalse(oci.isContainer());

        // Check some, but not all, attributes of inetOrgClass.
        Set<AttributeInfo> attrInfos = oci.getAttributeInfo();
        AttributeInfo info = AttributeInfoUtil.find("cn", attrInfos);
        assertEquals(AttributeInfoBuilder.build("cn", String.class,
                EnumSet.of(Flags.REQUIRED, Flags.MULTIVALUED)), info);
        info = AttributeInfoUtil.find("uid", attrInfos);
        assertEquals(AttributeInfoBuilder.build("uid", String.class, EnumSet.of(Flags.MULTIVALUED)), info);
        info = AttributeInfoUtil.find("givenName", attrInfos);
        assertEquals(AttributeInfoBuilder.build("givenName", String.class, EnumSet.of(Flags.MULTIVALUED)), info);
        info = AttributeInfoUtil.find("sn", attrInfos);
        assertEquals(AttributeInfoBuilder.build("sn", String.class,
                EnumSet.of(Flags.REQUIRED, Flags.MULTIVALUED)), info);

        // Operational attributes.
        info = AttributeInfoUtil.find(OperationalAttributes.PASSWORD_NAME, attrInfos);
        assertEquals(LdapConstants.PASSWORD, info);
    }

    @Test
    public void testGroupSchema() {
        LdapConfiguration config = newConfiguration(true);
        Schema schema = newFacade(config).schema();

        ObjectClassInfo oci = schema.findObjectClassInfo(ObjectClass.GROUP_NAME);
        assertFalse(oci.isContainer());

        Set<AttributeInfo> attrInfos = oci.getAttributeInfo();

        AttributeInfo info = AttributeInfoUtil.find("cn", attrInfos);
        assertEquals(AttributeInfoBuilder.build("cn", String.class, 
                EnumSet.of(Flags.REQUIRED, Flags.MULTIVALUED)), info);
    }

    @Test
    public void testAuthenticationOnlyForAccounts() {
        LdapConfiguration config = newConfiguration(true);
        Schema schema = newFacade(config).schema();
        Set<ObjectClassInfo> ocis = schema.getSupportedObjectClassesByOperation().get(AuthenticationApiOp.class);
        assertEquals(1, ocis.size());
        assertTrue(ocis.iterator().next().is(ObjectClass.ACCOUNT_NAME));
    }

    @Test
    public void testAllObjectClassesInSchema() {
        Schema schema = newFacade(newConfiguration(true)).schema();
        // Well, at least some of the most well-known.
        assertNotNull(schema.findObjectClassInfo("organization"));
        assertNotNull(schema.findObjectClassInfo("groupOfNames"));
        assertNotNull(schema.findObjectClassInfo("dNSDomain"));
        // top is abstract, so it shouldn't be in the schema.
        assertNull(schema.findObjectClassInfo("top"));
        // extensibleObject is auxiliary, so it shouldn't be in the schema.
        assertNull(schema.findObjectClassInfo("extensibleObject"));
    }

    @Test
    public void testArbitraryObjectClass() {
        Schema schema = newFacade(newConfiguration(true)).schema();

        ObjectClassInfo dnsDomainInfo = schema.findObjectClassInfo("dNSDomain");
        assertTrue(dnsDomainInfo.isContainer());

        Set<AttributeInfo> dnsDomainAttrInfos = dnsDomainInfo.getAttributeInfo();
        // Inherited from domain.
        AttributeInfo info = AttributeInfoUtil.find("dc", dnsDomainAttrInfos);
        assertEquals(AttributeInfoBuilder.build("dc", String.class, EnumSet.of(Flags.REQUIRED)), info);
        info = AttributeInfoUtil.find("telephoneNumber", dnsDomainAttrInfos);
        assertEquals(AttributeInfoBuilder.build("telephoneNumber", String.class, EnumSet.of(Flags.MULTIVALUED)), info);
        // Defined in dNSDomain.
        info = AttributeInfoUtil.find("MXRecord", dnsDomainAttrInfos);
        assertEquals(AttributeInfoBuilder.build("MXRecord", String.class, EnumSet.of(Flags.MULTIVALUED)), info);
    }

    @Test
    public void testAttributeTypes() {
        LdapConfiguration config = newConfiguration(true);
        Schema schema = newFacade(config).schema();
        ObjectClassInfo accountInfo = schema.findObjectClassInfo(ObjectClass.ACCOUNT_NAME);
        Set<AttributeInfo> accountAttrInfos = accountInfo.getAttributeInfo();

        assertEquals(String.class, AttributeInfoUtil.find("cn", accountAttrInfos).getType());
        assertEquals(String.class, AttributeInfoUtil.find("ou", accountAttrInfos).getType());
        assertEquals(String.class, AttributeInfoUtil.find("telephoneNumber", accountAttrInfos).getType());

        assertEquals(byte[].class, AttributeInfoUtil.find("audio", accountAttrInfos).getType());
        assertEquals(byte[].class, AttributeInfoUtil.find("jpegPhoto", accountAttrInfos).getType());
        assertEquals(byte[].class, AttributeInfoUtil.find("userCertificate", accountAttrInfos).getType());
        assertEquals(byte[].class, AttributeInfoUtil.find("x500UniqueIdentifier", accountAttrInfos).getType());
    }

    @Test
    public void testSyncNotSupported() {
        LdapConfiguration config = newConfiguration();
        LdapConnection conn = new LdapConnection(config);
        assertEquals(ServerType.OPENDS, conn.getServerType());
        Schema schema = newFacade(config).schema();
        assertTrue(schema.getSupportedObjectClassesByOperation().get(SyncApiOp.class).isEmpty());
    }
    
    @Test
    public void testGeneratedUserDN() throws InvalidNameException
    {
    	LdapConfiguration config = newConfiguration();
    	config.setUserRDNAttribute("uid");
    	config.setUserCreateContainerDN(ACME_USERS_DN);
    	LdapConnection connection = new LdapConnection(config);
    	LdapName generatedName = connection.getSchemaMapping().createLDAPName(ObjectClass.ACCOUNT, new Name(BUGS_BUNNY_UID));
    	LdapName actualName = new LdapName("uid="+BUGS_BUNNY_UID+","+ACME_USERS_DN);
		assertEquals(generatedName, actualName);		   	
    }
    
    @Test(expected=UnsupportedOperationException.class)
    public void testCreateUserDNWhenNoContainerDN() throws InvalidNameException
    {
    	LdapConfiguration config = newConfiguration();
    	config.setUserRDNAttribute("uid");
    	LdapConnection connection = new LdapConnection(config);
    	LdapName generatedName = connection.getSchemaMapping().createLDAPName(ObjectClass.ACCOUNT, new Name(BUGS_BUNNY_UID));
    	LdapName actualName = new LdapName("uid="+BUGS_BUNNY_UID+","+ACME_USERS_DN);
		assertEquals(generatedName, actualName);		   	
    }
    
    @Test
    public void testCreateUserDNSingleBase() throws InvalidNameException
    {
    	LdapConfiguration config = newConfiguration();
    	config.setUserRDNAttribute("uid");
    	config.setBaseContexts(ACME_DN);
    	LdapConnection connection = new LdapConnection(config);
    	LdapName generatedName = connection.getSchemaMapping().createLDAPName(ObjectClass.ACCOUNT, new Name(BUGS_BUNNY_UID));
    	LdapName actualName = new LdapName("uid="+BUGS_BUNNY_UID+","+ACME_DN);
		assertEquals(generatedName, actualName);		   	
    }
    
    @Test(expected=ConnectorException.class)
    public void testCreateUserDNWhenNoRDN() throws InvalidNameException
    {
    	LdapConfiguration config = newConfiguration();
    	config.setUserCreateContainerDN(ACME_USERS_DN);
    	LdapConnection connection = new LdapConnection(config);
    	LdapName generatedName = connection.getSchemaMapping().createLDAPName(ObjectClass.ACCOUNT, new Name(BUGS_BUNNY_UID));
    	LdapName actualName = new LdapName("uid="+BUGS_BUNNY_UID+","+ACME_USERS_DN);
		assertEquals(generatedName, actualName);		   	
    }
    
    @Test(expected=ConnectorException.class)
    public void testCreateUserDNWhenNoCreateConfig() throws InvalidNameException
    {
    	LdapConfiguration config = newConfiguration();
    	LdapConnection connection = new LdapConnection(config);
    	LdapName generatedName = connection.getSchemaMapping().createLDAPName(ObjectClass.ACCOUNT, new Name(BUGS_BUNNY_UID));
    	LdapName actualName = new LdapName("uid="+BUGS_BUNNY_UID+","+ACME_USERS_DN);
		assertEquals(generatedName, actualName);		   	
    }
    
    @Test
    public void testCreateUserDNSpecialChars() throws InvalidNameException
    {
    	LdapConfiguration config = newConfiguration();
    	config.setUserRDNAttribute("uid");
    	config.setUserCreateContainerDN(ACME_USERS_DN);
    	LdapConnection connection = new LdapConnection(config);    	
    	LdapName generatedName = connection.getSchemaMapping().createLDAPName(ObjectClass.ACCOUNT, new Name(NAME_WITH_COMMA));
    	LdapName actualName = new LdapName("uid="+Rdn.escapeValue(NAME_WITH_COMMA)+","+ACME_USERS_DN);
		assertEquals(generatedName, actualName);		   	
    }
    
    @Test
    public void testGeneratedGroupDN() throws InvalidNameException
    {
    	LdapConfiguration config = newConfiguration();
    	config.setGroupRDNAttribute("cn");
    	config.setGroupCreateContainerDN(ACME_GROUPS_DN);
    	LdapConnection connection = new LdapConnection(config);
    	LdapName generatedName = connection.getSchemaMapping().createLDAPName(ObjectClass.GROUP, new Name(BUGS_BUNNY_UID));
    	LdapName actualName = new LdapName("cn="+BUGS_BUNNY_UID+","+ACME_GROUPS_DN);
		assertEquals(generatedName, actualName);		   	
    }
    
    @Test(expected=UnsupportedOperationException.class)
    public void testCreateGroupDNWhenNoContainerDN() throws InvalidNameException
    {
    	LdapConfiguration config = newConfiguration();
    	config.setGroupRDNAttribute("cn");
    	LdapConnection connection = new LdapConnection(config);
    	LdapName generatedName = connection.getSchemaMapping().createLDAPName(ObjectClass.GROUP, new Name(BUGS_BUNNY_UID));
    	LdapName actualName = new LdapName("cn="+BUGS_BUNNY_UID+","+ACME_GROUPS_DN);
		assertEquals(generatedName, actualName);		   	
    }    
    
    @Test
    public void testCreateGroupDNSingleBase() throws InvalidNameException
    {
    	LdapConfiguration config = newConfiguration();
    	config.setGroupRDNAttribute("cn");
    	config.setBaseContexts(ACME_DN);
    	LdapConnection connection = new LdapConnection(config);
    	LdapName generatedName = connection.getSchemaMapping().createLDAPName(ObjectClass.GROUP, new Name(BUGS_BUNNY_UID));
    	LdapName actualName = new LdapName("cn="+BUGS_BUNNY_UID+","+ACME_DN);
		assertEquals(generatedName, actualName);		   	
    }
    
    @Test(expected=ConnectorException.class)
    public void testCreateGroupDNWhenNoRDN() throws InvalidNameException
    {
    	LdapConfiguration config = newConfiguration();
    	config.setGroupCreateContainerDN(ACME_GROUPS_DN);
    	LdapConnection connection = new LdapConnection(config);
    	LdapName generatedName = connection.getSchemaMapping().createLDAPName(ObjectClass.GROUP, new Name(BUGS_BUNNY_UID));
    	LdapName actualName = new LdapName("cn="+BUGS_BUNNY_UID+","+ACME_GROUPS_DN);
		assertEquals(generatedName, actualName);		   	
    }
    
    @Test(expected=ConnectorException.class)
    public void testCreateGroupDNWhenNoCreateConfig() throws InvalidNameException
    {
    	LdapConfiguration config = newConfiguration();
    	LdapConnection connection = new LdapConnection(config);
    	LdapName generatedName = connection.getSchemaMapping().createLDAPName(ObjectClass.GROUP, new Name(BUGS_BUNNY_UID));
    	LdapName actualName = new LdapName("cn="+BUGS_BUNNY_UID+","+ACME_GROUPS_DN);
		assertEquals(generatedName, actualName);		   	
    }
    
    @Test
    public void testCreateGroupDNSpecialChars() throws InvalidNameException
    {
    	LdapConfiguration config = newConfiguration();
    	config.setGroupRDNAttribute("cn");
    	config.setGroupCreateContainerDN(ACME_GROUPS_DN);
    	LdapConnection connection = new LdapConnection(config);    	
    	LdapName generatedName = connection.getSchemaMapping().createLDAPName(ObjectClass.GROUP, new Name(NAME_WITH_COMMA));
    	LdapName actualName = new LdapName("cn="+Rdn.escapeValue(NAME_WITH_COMMA)+","+ACME_GROUPS_DN);
		assertEquals(generatedName, actualName);		   	
    }
    
    @Test(expected = ConnectorException.class)
    public void testCreateObjectDN()
    {
    	LdapConfiguration config = newConfiguration();
    	LdapConnection connection = new LdapConnection(config);    	
    	connection.getSchemaMapping().createLDAPName(ObjectClass.ALL, new Name(NAME_WITH_COMMA));    	
    }


}