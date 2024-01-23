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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.EnumSet;
import java.util.Set;
import org.identityconnectors.framework.api.operations.AuthenticationApiOp;
import org.identityconnectors.framework.api.operations.SyncApiOp;
import org.identityconnectors.framework.common.objects.AttributeInfo;
import org.identityconnectors.framework.common.objects.AttributeInfoBuilder;
import org.identityconnectors.framework.common.objects.AttributeInfoUtil;
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
import org.junit.jupiter.api.Test;

public class LdapSchemaMappingTests extends LdapConnectorTestBase {

    // TODO operational attributes.
    // TODO test for operation option infos.

    @Test
    public void objectClassAttrIsReadOnly() {
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
    public void accountSchema() {
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
    public void authenticationOnlyForAccounts() {
        LdapConfiguration config = newConfiguration(true);
        Schema schema = newFacade(config).schema();
        Set<ObjectClassInfo> ocis = schema.getSupportedObjectClassesByOperation().get(AuthenticationApiOp.class);
        assertEquals(1, ocis.size());
        assertTrue(ocis.iterator().next().is(ObjectClass.ACCOUNT_NAME));
    }

    @Test
    public void allObjectClassesInSchema() {
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
    public void arbitraryObjectClass() {
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
    public void attributeTypes() {
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
        assertEquals(ServerType.OPENDJ, conn.getServerType());
        Schema schema = newFacade(config).schema();
        assertTrue(schema.getSupportedObjectClassesByOperation().get(SyncApiOp.class).isEmpty());
    }
}
