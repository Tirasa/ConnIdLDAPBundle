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
package net.tirasa.connid.bundles.ldap.modify;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import org.identityconnectors.common.IOUtil;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.api.ConnectorFacade;
import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.AttributeBuilder;
import org.identityconnectors.framework.common.objects.ConnectorObject;
import org.identityconnectors.framework.common.objects.Name;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.OperationOptionsBuilder;
import org.identityconnectors.framework.common.objects.OperationalAttributes;
import org.identityconnectors.framework.common.objects.Uid;
import net.tirasa.connid.bundles.ldap.LdapConfiguration;
import net.tirasa.connid.bundles.ldap.LdapConnectorTestBase;
import net.tirasa.connid.bundles.ldap.MyStatusManagement;
import net.tirasa.connid.bundles.ldap.schema.LdapSchemaMapping;

import org.identityconnectors.framework.common.objects.OperationOptions;
import org.junit.jupiter.api.Test;

public class LdapCreateTests extends LdapConnectorTestBase {

    // TODO test that we can create an entry of an object class not in the schema.
    // TODO test that we can't create an entry outside the configured base DNs.

    @Test
    public void createAccount() {
        LdapConfiguration config = newConfiguration();
        config.setBaseContexts(SMALL_COMPANY_DN);
        ConnectorFacade facade = newFacade(config);

        ConnectorObject created = doCreateAccount(facade);
        facade.delete(ObjectClass.ACCOUNT, created.getUid(), null);
    }

    @Test
    public void createAccountWhenReadingSchema() {
        LdapConfiguration config = newConfiguration();
        assertFalse(config.isReadSchema());
        config.setReadSchema(true);
        config.setBaseContexts(SMALL_COMPANY_DN);
        config.setAccountObjectClasses("inetOrgPerson");
        ConnectorFacade facade = newFacade(config);

        ConnectorObject created = doCreateAccount(facade);
        facade.delete(ObjectClass.ACCOUNT, created.getUid(), null);
    }

    @Test
    public void createAccountWhenUidNotDefault() {
        LdapConfiguration config = newConfiguration();
        assertFalse(config.getUidAttribute().equalsIgnoreCase("entryDN"));
        config.setUidAttribute("entryDN");
        config.setGidAttribute("entryDN");
        config.setBaseContexts(SMALL_COMPANY_DN);
        ConnectorFacade facade = newFacade(config);

        ConnectorObject created = doCreateAccount(facade);
        facade.delete(ObjectClass.ACCOUNT, created.getUid(), null);
    }

    private ConnectorObject doCreateAccount(final ConnectorFacade facade) {
        return doCreateAccount(facade, null);
    }

    private ConnectorObject doCreateAccount(final ConnectorFacade facade, final OperationOptions options) {
        Set<Attribute> attributes = new HashSet<>();
        Name name = new Name("uid=another.worker," + SMALL_COMPANY_DN);
        attributes.add(name);
        attributes.add(AttributeBuilder.build("uid", "another.worker"));
        attributes.add(AttributeBuilder.build("cn", "Another Worker"));
        attributes.add(AttributeBuilder.build("givenName", "Another"));
        attributes.add(AttributeBuilder.build("sn", "Worker"));

        final Uid uid = facade.create(ObjectClass.ACCOUNT, attributes, options);

        ConnectorObject newAccount = facade.getObject(ObjectClass.ACCOUNT, uid, options);
        assertEquals(name, newAccount.getName());
        return newAccount;
    }

    @Test
    public void createGroup() {
        LdapConfiguration config = newConfiguration();
        config.setBaseContexts(SMALL_COMPANY_DN);
        ConnectorFacade facade = newFacade(config);

        ConnectorObject created = doCreateGroup(facade);
        facade.delete(ObjectClass.GROUP, created.getUid(), null);
    }

    @Test
    public void createGroupWhenReadingSchema() {
        LdapConfiguration config = newConfiguration();
        assertFalse(config.isReadSchema());
        config.setReadSchema(true);
        config.setBaseContexts(SMALL_COMPANY_DN);
        config.setAccountObjectClasses("inetOrgPerson");
        ConnectorFacade facade = newFacade(config);

        ConnectorObject created = doCreateGroup(facade);
        facade.delete(ObjectClass.GROUP, created.getUid(), null);
    }

    @Test
    public void createGroupWhenUidNotDefault() {
        LdapConfiguration config = newConfiguration();
        assertFalse(config.getUidAttribute().equalsIgnoreCase("entryDN"));
        config.setUidAttribute("entryDN");
        config.setGidAttribute("entryDN");
        config.setBaseContexts(SMALL_COMPANY_DN);
        ConnectorFacade facade = newFacade(config);

        ConnectorObject created = doCreateGroup(facade);
        facade.delete(ObjectClass.GROUP, created.getUid(), null);
    }

    private ConnectorObject doCreateGroup(ConnectorFacade facade) {
        Set<Attribute> attributes = new HashSet<>();
        Name name = new Name("cn=Another Group," + SMALL_COMPANY_DN);
        attributes.add(name);
        attributes.add(AttributeBuilder.build("cn", "Another Group"));
        Uid uid = facade.create(ObjectClass.GROUP, attributes, null);

        ConnectorObject newGroup = facade.getObject(ObjectClass.GROUP, uid, null);
        assertEquals(name, newGroup.getName());
        return newGroup;
    }

    @Test
    public void createArbitrary() {
        LdapConfiguration config = newConfiguration();
        config.setBaseContexts(SMALL_COMPANY_DN);
        config.setAnyObjectClasses("top", "organization");
        ConnectorFacade facade = newFacade(config);

        ConnectorObject created = doCreateArbitrary(facade);
        facade.delete(LdapSchemaMapping.ANY_OBJECT_CLASS, created.getUid(), null);
    }

    @Test
    public void createArbitraryWhenReadingSchema() {
        LdapConfiguration config = newConfiguration(true);
        config.setBaseContexts(SMALL_COMPANY_DN);
        config.setAnyObjectClasses("top", "organization");
        ConnectorFacade facade = newFacade(config);

        ConnectorObject created = doCreateArbitrary(facade);
        facade.delete(LdapSchemaMapping.ANY_OBJECT_CLASS, created.getUid(), null);
    }

    @Test
    public void createArbitraryWhenUidNotDefault() {
        LdapConfiguration config = newConfiguration();
        assertFalse(config.getUidAttribute().equalsIgnoreCase("entryDN"));
        config.setUidAttribute("entryDN");
        config.setGidAttribute("entryDN");
        config.setAoidAttribute("entryDN");
        config.setAnyObjectNameAttributes("o");
        config.setBaseContexts(SMALL_COMPANY_DN);
        config.setAnyObjectClasses("top", "organization");
        ConnectorFacade facade = newFacade(config);

        ConnectorObject created = doCreateArbitrary(facade);
        facade.delete(LdapSchemaMapping.ANY_OBJECT_CLASS, created.getUid(), null);
    }

    private ConnectorObject doCreateArbitrary(ConnectorFacade facade) {
        // Let the arbitrary object class be organization.
        Set<Attribute> attributes = new HashSet<>();
        Name name = new Name("o=Smallest," + SMALL_COMPANY_DN);
        attributes.add(name);
        attributes.add(AttributeBuilder.build("o", "Smallest"));
        Uid uid = facade.create(LdapSchemaMapping.ANY_OBJECT_CLASS, attributes, null);

        ConnectorObject newObject = facade.getObject(LdapSchemaMapping.ANY_OBJECT_CLASS, uid, null);
        assertEquals(name, newObject.getName());
        return newObject;
    }

    @Test
    public void createDeviceWhenNameAttributesNotDefault() {
        LdapConfiguration config = newConfiguration();
        assertFalse(config.getUidAttribute().equalsIgnoreCase("entryDN"));
        config.setAnyObjectNameAttributes("cn");
        config.setBaseContexts(SMALL_COMPANY_DN);
        config.setAnyObjectClasses("top", "device");
        ConnectorFacade facade = newFacade(config);

        ConnectorObject created = doCreateDevice(facade);
        facade.delete(LdapSchemaMapping.ANY_OBJECT_CLASS, created.getUid(), null);
    }

    @Test
    public void createDeviceWhenObjectClassesNotDefault() {
        LdapConfiguration config = newConfiguration();
        assertFalse(config.getUidAttribute().equalsIgnoreCase("entryDN"));
        config.setAnyObjectClasses("top", "device");
        config.setBaseContexts(SMALL_COMPANY_DN);
        ConnectorFacade facade = newFacade(config);

        ConnectorObject created = doCreateDevice(facade);
        facade.delete(LdapSchemaMapping.ANY_OBJECT_CLASS, created.getUid(), null);
    }

    private ConnectorObject doCreateDevice(ConnectorFacade facade) {
        Set<Attribute> attributes = new HashSet<>();
        Name name = new Name(DEVICE_0_DN);
        attributes.add(name);
        attributes.add(AttributeBuilder.build("cn", DEVICE_0_CN));
        attributes.add(AttributeBuilder.build("serialNumber", DEVICE_0_SERIALNUMBER));

        Uid uid = facade.create(LdapSchemaMapping.ANY_OBJECT_CLASS, attributes, null);

        ConnectorObject newObject = facade.getObject(LdapSchemaMapping.ANY_OBJECT_CLASS, uid, null);
        assertEquals(name, newObject.getName());
        return newObject;
    }

    @Test
    public void createBinaryAttributes() throws IOException {
        ConnectorFacade facade = newFacade();

        Set<Attribute> attributes = new HashSet<>();
        attributes.add(new Name("uid=daffy.duck,ou=Users,o=Acme,dc=example,dc=com"));
        attributes.add(AttributeBuilder.build("uid", "daffy.duck"));
        attributes.add(AttributeBuilder.build("cn", "Daffy Duck"));
        attributes.add(AttributeBuilder.build("givenName", "Daffy"));
        attributes.add(AttributeBuilder.build("sn", "Duck"));
        byte[] certificate = IOUtil.getResourceAsBytes(LdapCreateTests.class, "certificate.cert");
        attributes.add(AttributeBuilder.build("userCertificate", certificate));
        byte[] photo = IOUtil.getResourceAsBytes(LdapCreateTests.class, "photo.jpg");
        attributes.add(AttributeBuilder.build("jpegPhoto", photo));

        Uid uid = facade.create(ObjectClass.ACCOUNT, attributes, null);

        ConnectorObject newAccount = facade.getObject(ObjectClass.ACCOUNT, uid,
                new OperationOptionsBuilder().setAttributesToGet("userCertificate", "jpegPhoto").build());
        byte[] storedCertificate = (byte[]) newAccount.getAttributeByName("userCertificate").getValue().get(0);
        assertTrue(Arrays.equals(certificate, storedCertificate));
        byte[] storedPhoto = (byte[]) newAccount.getAttributeByName("jpegPhoto").getValue().get(0);
        assertTrue(Arrays.equals(photo, storedPhoto));
        facade.delete(ObjectClass.ACCOUNT, newAccount.getUid(), null);
    }

    @Test
    public void createPassword() {
        ConnectorFacade facade = newFacade();

        Set<Attribute> attributes = new HashSet<>();
        attributes.add(new Name("uid=daffy.duck,ou=Users,o=Acme,dc=example,dc=com"));
        attributes.add(AttributeBuilder.build("uid", "daffy.duck"));
        attributes.add(AttributeBuilder.build("cn", "Daffy Duck"));
        attributes.add(AttributeBuilder.build("givenName", "Daffy"));
        attributes.add(AttributeBuilder.build("sn", "Duck"));
        GuardedString password = new GuardedString("I.hate.rabbits".toCharArray());
        attributes.add(AttributeBuilder.buildPassword(password));
        Uid uid = facade.create(ObjectClass.ACCOUNT, attributes, null);

        facade.authenticate(ObjectClass.ACCOUNT, "daffy.duck", password, null);
        facade.delete(ObjectClass.ACCOUNT, uid, null);
    }

    @Test
    public void createDisabled() {
        LdapConfiguration config = new LdapConfiguration();

        config.setHost("localhost");
        config.setPort(PORT);
        config.setBaseContexts(ACME_DN, BIG_COMPANY_DN);
        config.setPrincipal(ADMIN_DN);
        config.setCredentials(ADMIN_PASSWORD);
        config.setReadSchema(false);
        config.setStatusManagementClass(MyStatusManagement.class.getName());

        ConnectorFacade facade = newFacade(config);

        Set<Attribute> attributes = new HashSet<>();
        attributes.add(new Name("uid=daffy2,ou=Users,o=Acme,dc=example,dc=com"));
        attributes.add(AttributeBuilder.build("uid", "daffy2"));
        attributes.add(AttributeBuilder.build("cn", "Daffy Duck 2"));
        attributes.add(AttributeBuilder.build("givenName", "Daffy"));
        attributes.add(AttributeBuilder.build("sn", "Duck"));
        GuardedString password = new GuardedString("I.hate.rabbits".toCharArray());
        attributes.add(AttributeBuilder.buildPassword(password));
        attributes.add(AttributeBuilder.buildEnabled(false));

        Uid uid = facade.create(ObjectClass.ACCOUNT, attributes, null);
        assertNotNull(uid);

        OperationOptionsBuilder builder = new OperationOptionsBuilder();
        builder.setAttributesToGet(Arrays.asList(new String[] { "description", OperationalAttributes.ENABLE_NAME }));
        ConnectorObject obj = facade.getObject(ObjectClass.ACCOUNT, uid, builder.build());
        assertNotNull(obj);

        Attribute status = obj.getAttributeByName(OperationalAttributes.ENABLE_NAME);
        assertNotNull(status);
        assertFalse(status.getValue().isEmpty());
        assertFalse((Boolean) status.getValue().get(0));
        facade.delete(ObjectClass.ACCOUNT, uid, null);
    }

    @Test
    public void issueLDAP12() {
        LdapConfiguration config = newConfiguration();
        config.setBaseContexts(SMALL_COMPANY_DN);
        config.setUidAttribute("sn");
        ConnectorFacade facade = newFacade(config);
        ConnectorObject created = doCreateAccount(facade,
                new OperationOptionsBuilder().setAttributesToGet("givenName").build());
        facade.delete(ObjectClass.ACCOUNT, created.getUid(), null);
    }
}
