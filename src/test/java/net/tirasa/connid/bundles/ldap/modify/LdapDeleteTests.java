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

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.HashSet;
import java.util.Set;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.api.ConnectorFacade;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.AttributeBuilder;
import org.identityconnectors.framework.common.objects.ConnectorObject;
import org.identityconnectors.framework.common.objects.Name;
import org.identityconnectors.framework.common.objects.ObjectClass;
import net.tirasa.connid.bundles.ldap.LdapConnectorTestBase;
import org.junit.jupiter.api.Test;

public class LdapDeleteTests extends LdapConnectorTestBase {

    @Test
    public void cannotDeleteExistingUidButWrongObjectClass() {
        ConnectorFacade facade = newFacade();
        ConnectorObject organization = searchByAttribute(
                facade, new ObjectClass("organization"), new Name(BIG_COMPANY_DN));
        // Should fail because the object class passed to delete() is not ORGANIZATION.
        assertThrows(ConnectorException.class, () -> facade.delete(ObjectClass.ACCOUNT, organization.getUid(), null));
    }

    @Test
    public void cannotDeleteNonEmptyDN() {
        // TODO: not sure this is the right behavior. Perhaps should instead
        // recursively delete everything under the deleted entry.
        ConnectorFacade facade = newFacade();
        ObjectClass oclass = new ObjectClass("organization");
        ConnectorObject organization = searchByAttribute(facade, oclass, new Name(ACME_DN));
        assertThrows(ConnectorException.class, () -> facade.delete(oclass, organization.getUid(), null));
    }

    @Test
    public void delete() {
        ConnectorFacade facade = newFacade();
        ConnectorObject account = searchByAttribute(facade, ObjectClass.ACCOUNT, new Name(BUGS_BUNNY_DN));
        facade.delete(ObjectClass.ACCOUNT, account.getUid(), null);

        ConnectorObject deletedAccount = searchByAttribute(facade, ObjectClass.ACCOUNT, new Name(BUGS_BUNNY_DN));
        assertNull(deletedAccount);
        Set<Attribute> attributes = new HashSet<>();
        attributes.add(new Name(BUGS_BUNNY_DN));
        attributes.add(AttributeBuilder.build("uid", "bugs.bunny", "bbunny"));
        attributes.add(AttributeBuilder.build("cn", "Bugs Bunny"));
        attributes.add(AttributeBuilder.build("sn", "Bunny"));
        attributes.add(AttributeBuilder.buildPassword(new GuardedString("carrot".toCharArray())));
        facade.create(ObjectClass.ACCOUNT, attributes, null);
    }
}
