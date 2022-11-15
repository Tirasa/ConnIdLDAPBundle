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

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.identityconnectors.common.IOUtil;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.api.ConnectorFacade;
import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.AttributeBuilder;
import org.identityconnectors.framework.common.objects.ConnectorObject;
import org.identityconnectors.framework.common.objects.Name;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.OperationOptions;
import org.identityconnectors.framework.common.objects.OperationOptionsBuilder;
import org.identityconnectors.framework.common.objects.OperationalAttributes;
import org.identityconnectors.framework.common.objects.Uid;
import net.tirasa.connid.bundles.ldap.LdapConfiguration;
import net.tirasa.connid.bundles.ldap.LdapConnectorTestBase;
import net.tirasa.connid.bundles.ldap.MyStatusManagement;
import org.identityconnectors.common.CollectionUtil;
import org.identityconnectors.framework.common.objects.AttributeDelta;
import org.identityconnectors.framework.common.objects.AttributeDeltaBuilder;
import org.identityconnectors.test.common.TestHelpers;
import org.junit.jupiter.api.Test;

public class LdapUpdateTests extends LdapConnectorTestBase {

    private static final String DAFFY_DUCK_DN = "uid=daffy.duck,ou=Users,o=Acme,dc=example,dc=com";

    // XXX need tests for the case when the one of the modified (or removed)
    // attribute is the Name or especially Uid.
    private static final String NUMBER1 = "+1 800 123 4567";

    private static final String NUMBER2 = "+1 800 765 4321";

    private static final String NUMBER3 = "+1 800 765 9876";

    @Override
    protected boolean restartServerAfterEachTest() {
        return true;
    }

    @Test
    public void updateDelta() {
        // 1. take user and set attribute
        ConnectorFacade facade = newFacade();
        ConnectorObject bugs = searchByAttribute(facade, ObjectClass.ACCOUNT, new Name(BUGS_BUNNY_DN));

        facade.update(
                ObjectClass.ACCOUNT,
                bugs.getUid(),
                Collections.singleton(AttributeBuilder.build("telephoneNumber", NUMBER1)),
                null);

        OperationOptions options = new OperationOptionsBuilder().setAttributesToGet("telephoneNumber").build();
        bugs = facade.getObject(ObjectClass.ACCOUNT, bugs.getUid(), options);
        List<Object> numberAttr = bugs.getAttributeByName("telephoneNumber").getValue();
        assertEquals(1, numberAttr.size());
        assertEquals(NUMBER1, numberAttr.get(0));

        // 2. updateDelta with values to add and to remove
        AttributeDelta delta = AttributeDeltaBuilder.build(
                "telephoneNumber", Collections.singletonList(NUMBER2), Collections.singletonList(NUMBER1));
        facade.updateDelta(ObjectClass.ACCOUNT, bugs.getUid(), Collections.singleton(delta), null);

        bugs = facade.getObject(ObjectClass.ACCOUNT, bugs.getUid(), options);
        numberAttr = bugs.getAttributeByName("telephoneNumber").getValue();
        assertEquals(1, numberAttr.size());
        assertEquals(NUMBER2, numberAttr.get(0));

        // 3. updateDelta with values to add
        delta = AttributeDeltaBuilder.build(
                "telephoneNumber", Collections.singletonList(NUMBER1), Collections.emptyList());
        facade.updateDelta(ObjectClass.ACCOUNT, bugs.getUid(), Collections.singleton(delta), null);

        bugs = facade.getObject(ObjectClass.ACCOUNT, bugs.getUid(), options);
        numberAttr = bugs.getAttributeByName("telephoneNumber").getValue();
        assertEquals(2, numberAttr.size());
        assertTrue(numberAttr.contains(NUMBER1));
        assertTrue(numberAttr.contains(NUMBER2));

        // 4. updateDelta with values to replace
        assertDoesNotThrow(() -> facade.authenticate(
                ObjectClass.ACCOUNT, BUGS_BUNNY_UID, new GuardedString("carrot".toCharArray()), null));

        delta = AttributeDeltaBuilder.build("telephoneNumber", CollectionUtil.newList(NUMBER1, NUMBER3));
        GuardedString newPwd = new GuardedString("newPwd".toCharArray());
        facade.updateDelta(
                ObjectClass.ACCOUNT,
                bugs.getUid(),
                CollectionUtil.newSet(delta, AttributeDeltaBuilder.buildPassword(newPwd)),
                null);

        bugs = facade.getObject(ObjectClass.ACCOUNT, bugs.getUid(), options);
        numberAttr = bugs.getAttributeByName("telephoneNumber").getValue();
        assertEquals(2, numberAttr.size());
        assertTrue(numberAttr.contains(NUMBER1));
        assertTrue(numberAttr.contains(NUMBER3));

        assertDoesNotThrow(() -> facade.authenticate(ObjectClass.ACCOUNT, BUGS_BUNNY_UID, newPwd, null));
    }

    @Test
    public void simpleAddRemoveAttrs() {
        ConnectorFacade facade = newFacade();
        ConnectorObject bugs = searchByAttribute(facade, ObjectClass.ACCOUNT, new Name(BUGS_BUNNY_DN));

        Attribute number1 = AttributeBuilder.build("telephoneNumber", NUMBER1);

        Uid newUid = facade.addAttributeValues(
                ObjectClass.ACCOUNT, bugs.getUid(), Collections.singleton(number1), null);

        OperationOptionsBuilder builder = new OperationOptionsBuilder();
        builder.setAttributesToGet("telephoneNumber");
        OperationOptions options = builder.build();

        bugs = facade.getObject(ObjectClass.ACCOUNT, newUid, options);
        List<Object> numberAttr = bugs.getAttributeByName("telephoneNumber").getValue();
        assertEquals(NUMBER1, numberAttr.get(0));
        assertEquals(1, numberAttr.size());

        Attribute number2 = AttributeBuilder.build("telephoneNumber", NUMBER2);
        newUid = facade.addAttributeValues(ObjectClass.ACCOUNT, bugs.getUid(), Collections.singleton(number2), null);

        bugs = facade.getObject(ObjectClass.ACCOUNT, newUid, options);
        numberAttr = bugs.getAttributeByName("telephoneNumber").getValue();
        assertEquals(NUMBER1, numberAttr.get(0));
        assertEquals(NUMBER2, numberAttr.get(1));
        assertEquals(2, numberAttr.size());

        newUid = facade.removeAttributeValues(
                ObjectClass.ACCOUNT, bugs.getUid(), CollectionUtil.newSet(number1, number2), null);

        bugs = facade.getObject(ObjectClass.ACCOUNT, newUid, options);
        assertTrue(bugs.getAttributeByName("telephoneNumber").getValue().isEmpty());
    }

    @Test
    public void rename() {
        ConnectorFacade facade = newFacade();
        ConnectorObject bugs = searchByAttribute(facade, ObjectClass.ACCOUNT, new Name(BUGS_BUNNY_DN));

        Name name = new Name(DAFFY_DUCK_DN);
        Attribute number = AttributeBuilder.build("telephoneNumber", NUMBER1);
        Uid newUid = facade.update(ObjectClass.ACCOUNT, bugs.getUid(), CollectionUtil.newSet(name, number), null);

        OperationOptionsBuilder builder = new OperationOptionsBuilder().setAttributesToGet("telephoneNumber");

        ConnectorObject daffy = facade.getObject(ObjectClass.ACCOUNT, newUid, builder.build());
        assertEquals(name, daffy.getName());
        assertEquals(NUMBER1, daffy.getAttributeByName("telephoneNumber").getValue().get(0));
    }

    @Test
    public void renameWhenUidNotDefault() {
        LdapConfiguration config = newConfiguration();
        assertFalse(config.getUidAttribute().equalsIgnoreCase("entryDN"));
        config.setUidAttribute("entryDN");
        config.setGidAttribute("entryDN");
        ConnectorFacade facade = newFacade(config);
        ConnectorObject bugs = searchByAttribute(facade, ObjectClass.ACCOUNT, new Name(BUGS_BUNNY_DN));

        Name name = new Name(DAFFY_DUCK_DN);
        Uid newUid = facade.update(ObjectClass.ACCOUNT, bugs.getUid(), Collections.singleton(name), null);

        // Since they are both the entry DN.
        assertEquals(name.getNameValue(), newUid.getUidValue());
        ConnectorObject daffy = facade.getObject(ObjectClass.ACCOUNT, newUid, null);
        assertEquals(name, daffy.getName());
    }

    @Test
    public void emptyAttributeValueRemovesAttribute() {
        ConnectorFacade facade = newFacade();
        ConnectorObject bugs = searchByAttribute(facade, ObjectClass.ACCOUNT,
                new Name(BUGS_BUNNY_DN));

        Attribute number = AttributeBuilder.build("telephoneNumber", NUMBER1);
        facade.update(ObjectClass.ACCOUNT, bugs.getUid(), Collections.singleton(number), null);

        Attribute noNumber = AttributeBuilder.build("telephoneNumber");
        assertNull(noNumber.getValue());
        Uid newUid = facade.update(ObjectClass.ACCOUNT, bugs.getUid(), Collections.singleton(noNumber), null);

        OperationOptionsBuilder builder = new OperationOptionsBuilder();
        builder.setAttributesToGet("telephoneNumber");

        bugs = facade.getObject(ObjectClass.ACCOUNT, newUid, builder.build());
        assertTrue(bugs.getAttributeByName("telephoneNumber").getValue().isEmpty());
    }

    @Test
    public void updateBinaryAttributes() throws IOException {
        ConnectorFacade facade = newFacade();
        ConnectorObject bugs = searchByAttribute(facade, ObjectClass.ACCOUNT, new Name(BUGS_BUNNY_DN));

        byte[] certificate = IOUtil.getResourceAsBytes(LdapUpdateTests.class, "certificate.cert");
        Attribute certAttr = AttributeBuilder.build("userCertificate", certificate);
        Uid newUid = facade.update(ObjectClass.ACCOUNT, bugs.getUid(), Collections.singleton(certAttr), null);

        byte[] photo = IOUtil.getResourceAsBytes(LdapUpdateTests.class, "photo.jpg");
        Attribute photoAttr = AttributeBuilder.build("jpegPhoto", photo);
        newUid = facade.addAttributeValues(ObjectClass.ACCOUNT, newUid, Collections.singleton(photoAttr), null);

        OperationOptionsBuilder builder = new OperationOptionsBuilder();
        builder.setAttributesToGet("userCertificate", "jpegPhoto");

        bugs = facade.getObject(ObjectClass.ACCOUNT, newUid, builder.build());
        byte[] storedCertificate = (byte[]) bugs.getAttributeByName("userCertificate").getValue().get(0);
        assertTrue(Arrays.equals(certificate, storedCertificate));
        byte[] storedPhoto = (byte[]) bugs.getAttributeByName("jpegPhoto").getValue().get(0);
        assertTrue(Arrays.equals(photo, storedPhoto));
    }

    @Test
    public void adminCanChangePassword() {
        ConnectorFacade facade = newFacade();
        ConnectorObject elmer = searchByAttribute(facade, ObjectClass.ACCOUNT, new Name(ELMER_FUDD_DN));

        GuardedString password = new GuardedString("shotgun".toCharArray());
        Attribute pwdAttr = AttributeBuilder.buildPassword(password);
        facade.update(ObjectClass.ACCOUNT, elmer.getUid(), Collections.singleton(pwdAttr), null);

        // Now test that the user can login with the new password and execute an operation.
        LdapConfiguration config = newConfiguration();
        config.setPrincipal(ELMER_FUDD_DN);
        config.setCredentials(password);
        // since the user doesn't have the privilege.
        facade = newFacade(config);
        List<ConnectorObject> objects = TestHelpers.searchToList(facade, new ObjectClass("organization"), null);
        assertNotNull(findByAttribute(objects, Name.NAME, ACME_DN));
    }

    @Test
    public void userCanChangePassword() {
        LdapConfiguration config = newConfiguration();
        config.setPrincipal(BUGS_BUNNY_DN);
        config.setCredentials(new GuardedString("carrot".toCharArray()));
        ConnectorFacade facade = newFacade(config);
        ConnectorObject bugs = searchByAttribute(facade, ObjectClass.ACCOUNT, new Name(BUGS_BUNNY_DN));

        GuardedString password = new GuardedString("cabbage".toCharArray());
        Attribute pwdAttr = AttributeBuilder.buildPassword(password);
        facade.update(ObjectClass.ACCOUNT, bugs.getUid(), Collections.singleton(pwdAttr), null);

        // Now test that the user can login with the new password and execute an operation.
        config.setCredentials(password);
        facade = newFacade(config);
        ConnectorObject elmer = searchByAttribute(facade, ObjectClass.ACCOUNT, new Name(ELMER_FUDD_DN));
        assertNotNull(elmer);
    }

    @Test
    public void enableDisable() {
        LdapConfiguration config = new LdapConfiguration();
        config.setHost("localhost");
        config.setPort(PORT);
        config.setBaseContexts(ACME_DN, BIG_COMPANY_DN);
        config.setPrincipal(ADMIN_DN);
        config.setCredentials(ADMIN_PASSWORD);
        config.setReadSchema(false);
        config.setStatusManagementClass(MyStatusManagement.class.getName());

        ConnectorFacade facade = newFacade(config);

        ConnectorObject bugs = searchByAttribute(facade, ObjectClass.ACCOUNT, new Name(BUGS_BUNNY_DN));

        Attribute status = AttributeBuilder.buildEnabled(false);
        Uid uid = facade.update(ObjectClass.ACCOUNT, bugs.getUid(), Collections.singleton(status), null);
        assertNotNull(uid);

        ConnectorObject obj = facade.getObject(ObjectClass.ACCOUNT, uid, null);
        assertNotNull(obj);

        status = obj.getAttributeByName(OperationalAttributes.ENABLE_NAME);
        assertNotNull(status);
        assertFalse(status.getValue().isEmpty());
        assertFalse((Boolean) status.getValue().get(0));

        status = AttributeBuilder.buildEnabled(true);
        uid = facade.update(ObjectClass.ACCOUNT, bugs.getUid(), Collections.singleton(status), null);
        assertNotNull(uid);

        obj = facade.getObject(ObjectClass.ACCOUNT, uid, null);
        assertNotNull(obj);

        status = obj.getAttributeByName(OperationalAttributes.ENABLE_NAME);
        assertNotNull(status);
        assertFalse(status.getValue().isEmpty());
        assertTrue((Boolean) status.getValue().get(0));
    }

    @Test
    public void renameDnAttribute() {
        ConnectorFacade facade = newFacade();
        ConnectorObject bugs = searchByAttribute(facade, ObjectClass.ACCOUNT, new Name(RENAME_ONE_TEST_DN));

        Name name = new Name(RENAME_TWO_TEST_DN);
        Attribute uidAttribute = AttributeBuilder.build("uid", "rename.one");
        Uid newUid = facade.update(ObjectClass.ACCOUNT, bugs.getUid(), CollectionUtil.newSet(name, uidAttribute), null);

        OperationOptionsBuilder builder = new OperationOptionsBuilder();
        builder.setAttributesToGet("uid");

        ConnectorObject renameTwo = facade.getObject(ObjectClass.ACCOUNT, newUid, builder.build());
        assertEquals(name, renameTwo.getName());
        assertEquals("rename.two", renameTwo.getAttributeByName("uid").getValue().get(0));
    }
}
