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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

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
import org.identityconnectors.framework.common.objects.OperationOptions;
import org.junit.Test;

public class LdapCreateTests extends LdapConnectorTestBase {

    // TODO test that we can create an entry of an object class not in the schema.
    // TODO test that we can't create an entry outside the configured base DNs.
    @Override
    protected boolean restartServerAfterEachTest() {
        return true;
    }

    @Test
    public void testCreateAccount() {
        LdapConfiguration config = newConfiguration();
        config.setBaseContexts(SMALL_COMPANY_DN);
        ConnectorFacade facade = newFacade(config);

        doCreateAccount(facade);
    }

    @Test
    public void testCreateAccountWhenReadingSchema() {
        LdapConfiguration config = newConfiguration();
        assertFalse(config.isReadSchema());
        config.setReadSchema(true);
        config.setBaseContexts(SMALL_COMPANY_DN);
        config.setAccountObjectClasses("inetOrgPerson");
        ConnectorFacade facade = newFacade(config);

        doCreateAccount(facade);
    }

    @Test
    public void testCreateAccountWhenUidNotDefault() {
        LdapConfiguration config = newConfiguration();
        assertFalse(config.getUidAttribute().equalsIgnoreCase("entryDN"));
        config.setUidAttribute("entryDN");
        config.setGidAttribute("entryDN");
        config.setBaseContexts(SMALL_COMPANY_DN);
        ConnectorFacade facade = newFacade(config);

        doCreateAccount(facade);
    }

    private void doCreateAccount(final ConnectorFacade facade) {
        doCreateAccount(facade, null);
    }

    private void doCreateAccount(final ConnectorFacade facade, final OperationOptions options) {
        Set<Attribute> attributes = new HashSet<Attribute>();
        Name name = new Name("uid=another.worker," + SMALL_COMPANY_DN);
        attributes.add(name);
        attributes.add(AttributeBuilder.build("uid", "another.worker"));
        attributes.add(AttributeBuilder.build("cn", "Another Worker"));
        attributes.add(AttributeBuilder.build("givenName", "Another"));
        attributes.add(AttributeBuilder.build("sn", "Worker"));

        final Uid uid = facade.create(ObjectClass.ACCOUNT, attributes, options);

        ConnectorObject newAccount = facade.getObject(ObjectClass.ACCOUNT, uid, options);
        assertEquals(name, newAccount.getName());
    }

    @Test
    public void testCreateGroup() {
        LdapConfiguration config = newConfiguration();
        config.setBaseContexts(SMALL_COMPANY_DN);
        ConnectorFacade facade = newFacade(config);

        doCreateGroup(facade);
    }

    @Test
    public void testCreateGroupWhenReadingSchema() {
        LdapConfiguration config = newConfiguration();
        assertFalse(config.isReadSchema());
        config.setReadSchema(true);
        config.setBaseContexts(SMALL_COMPANY_DN);
        config.setAccountObjectClasses("inetOrgPerson");
        ConnectorFacade facade = newFacade(config);

        doCreateGroup(facade);
    }

    @Test
    public void testCreateGroupWhenUidNotDefault() {
        LdapConfiguration config = newConfiguration();
        assertFalse(config.getUidAttribute().equalsIgnoreCase("entryDN"));
        config.setUidAttribute("entryDN");
        config.setGidAttribute("entryDN");
        config.setBaseContexts(SMALL_COMPANY_DN);
        ConnectorFacade facade = newFacade(config);

        doCreateGroup(facade);
    }

    private void doCreateGroup(ConnectorFacade facade) {
        Set<Attribute> attributes = new HashSet<Attribute>();
        Name name = new Name("cn=Another Group," + SMALL_COMPANY_DN);
        attributes.add(name);
        attributes.add(AttributeBuilder.build("cn", "Another Group"));
        Uid uid = facade.create(ObjectClass.GROUP, attributes, null);

        ConnectorObject newGroup = facade.getObject(ObjectClass.GROUP, uid, null);
        assertEquals(name, newGroup.getName());
    }

    @Test
    public void testCreateArbitrary() {
        LdapConfiguration config = newConfiguration();
        config.setBaseContexts(SMALL_COMPANY_DN);
        ConnectorFacade facade = newFacade(config);

        doCreateArbitrary(facade);
    }

    @Test
    public void testCreateArbitraryWhenReadingSchema() {
        LdapConfiguration config = newConfiguration(true);
        config.setBaseContexts(SMALL_COMPANY_DN);
        ConnectorFacade facade = newFacade(config);

        doCreateArbitrary(facade);
    }

    @Test
    public void testCreateArbitraryWhenUidNotDefault() {
        LdapConfiguration config = newConfiguration();
        assertFalse(config.getUidAttribute().equalsIgnoreCase("entryDN"));
        config.setUidAttribute("entryDN");
        config.setGidAttribute("entryDN");
        config.setBaseContexts(SMALL_COMPANY_DN);
        ConnectorFacade facade = newFacade(config);

        doCreateArbitrary(facade);
    }

    private void doCreateArbitrary(ConnectorFacade facade) {
        // Let the arbitrary object class be organization.
        Set<Attribute> attributes = new HashSet<Attribute>();
        Name name = new Name("o=Smallest," + SMALL_COMPANY_DN);
        attributes.add(name);
        attributes.add(AttributeBuilder.build("o", "Smallest"));
        ObjectClass oclass = new ObjectClass("organization");
        Uid uid = facade.create(oclass, attributes, null);

        ConnectorObject newObject = facade.getObject(oclass, uid, null);
        assertEquals(name, newObject.getName());
    }

    @Test
    public void testCreateBinaryAttributes() throws IOException {
        ConnectorFacade facade = newFacade();

        Set<Attribute> attributes = new HashSet<Attribute>();
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
    }

    @Test
    public void testCreatePassword() {
        ConnectorFacade facade = newFacade();

        Set<Attribute> attributes = new HashSet<Attribute>();
        attributes.add(new Name("uid=daffy.duck,ou=Users,o=Acme,dc=example,dc=com"));
        attributes.add(AttributeBuilder.build("uid", "daffy.duck"));
        attributes.add(AttributeBuilder.build("cn", "Daffy Duck"));
        attributes.add(AttributeBuilder.build("givenName", "Daffy"));
        attributes.add(AttributeBuilder.build("sn", "Duck"));
        GuardedString password = new GuardedString("I.hate.rabbits".toCharArray());
        attributes.add(AttributeBuilder.buildPassword(password));
        facade.create(ObjectClass.ACCOUNT, attributes, null);

        facade.authenticate(ObjectClass.ACCOUNT, "daffy.duck", password, null);
    }

    @Test
    public void testCreateDisabled() {
        final LdapConfiguration config = new LdapConfiguration();

        config.setHost("localhost");
        config.setPort(PORT);
        config.setBaseContexts(ACME_DN, BIG_COMPANY_DN);
        config.setPrincipal(ADMIN_DN);
        config.setCredentials(ADMIN_PASSWORD);
        config.setReadSchema(false);
        config.setStatusManagementClass(MyStatusManagement.class.getName());

        ConnectorFacade facade = newFacade(config);

        Set<Attribute> attributes = new HashSet<Attribute>();
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
    }

    @Test
    public void issueLDAP12() {
        LdapConfiguration config = newConfiguration();
        config.setBaseContexts(SMALL_COMPANY_DN);
        config.setUidAttribute("sn");
        doCreateAccount(newFacade(config), new OperationOptionsBuilder().setAttributesToGet("givenName").build());
    }
}
