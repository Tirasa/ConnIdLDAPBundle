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
package net.tirasa.connid.bundles.ldap.search;

import static net.tirasa.connid.bundles.ldap.search.LdapFilter.forEntryDN;
import static net.tirasa.connid.bundles.ldap.search.LdapFilter.forNativeFilter;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.identityconnectors.framework.common.objects.AttributeBuilder;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.filter.ContainsAllValuesFilter;
import org.identityconnectors.framework.common.objects.filter.ContainsFilter;
import org.identityconnectors.framework.common.objects.filter.EndsWithFilter;
import org.identityconnectors.framework.common.objects.filter.EqualsFilter;
import org.identityconnectors.framework.common.objects.filter.FilterBuilder;
import org.identityconnectors.framework.common.objects.filter.GreaterThanFilter;
import org.identityconnectors.framework.common.objects.filter.GreaterThanOrEqualFilter;
import org.identityconnectors.framework.common.objects.filter.LessThanFilter;
import org.identityconnectors.framework.common.objects.filter.LessThanOrEqualFilter;
import org.identityconnectors.framework.common.objects.filter.StartsWithFilter;
import net.tirasa.connid.bundles.ldap.LdapConfiguration;
import net.tirasa.connid.bundles.ldap.LdapConnection;
import net.tirasa.connid.bundles.ldap.LdapConnectorTestBase;
import net.tirasa.connid.bundles.ldap.schema.LdapSchemaMapping;
import org.identityconnectors.framework.common.objects.filter.EqualsIgnoreCaseFilter;
import org.junit.jupiter.api.Test;

public class LdapFilterTranslatorTests extends LdapConnectorTestBase {

    @Test
    public void and() {
        assertEquals(forNativeFilter("(&(foo=1)(bar=2))"), newTranslator().createAndExpression(
                forNativeFilter("(foo=1)"),
                forNativeFilter("(bar=2)")));
        assertEquals(forEntryDN("dc=example,dc=com").withNativeFilter("(foo=1)"), newTranslator().
                createAndExpression(
                        forEntryDN("dc=example,dc=com"),
                        forNativeFilter("(foo=1)")));
        assertEquals(forEntryDN("dc=example,dc=com").withNativeFilter("(&(foo=1)(bar=2))"), newTranslator().
                createAndExpression(
                        forEntryDN("dc=example,dc=com").withNativeFilter("(foo=1)"),
                        forNativeFilter("(bar=2)")));
        assertNull(newTranslator().createAndExpression(
                forEntryDN("dc=example,dc=com").withNativeFilter("(foo=1)"),
                forEntryDN("dc=example,dc=org").withNativeFilter("(bar=2)")));
    }

    @Test
    public void or() {
        assertEquals(forNativeFilter("(|(foo=1)(bar=2))"),
                newTranslator().createOrExpression(forNativeFilter("(foo=1)"), forNativeFilter(
                        "(bar=2)")));
        assertNull(newTranslator().createOrExpression(
                forEntryDN("dc=example,dc=com"), forNativeFilter("(foo=1)")));
    }

    @Test
    public void contains() {
        ContainsFilter filter = (ContainsFilter) FilterBuilder.contains(AttributeBuilder.build("foo", ""));
        assertEquals(forNativeFilter("(foo=*)"), newTranslator().createContainsExpression(filter, false));

        filter = (ContainsFilter) FilterBuilder.contains(AttributeBuilder.build("foo", "bar"));
        assertEquals(forNativeFilter("(foo=*bar*)"), newTranslator().createContainsExpression(filter, false));
    }

    @Test
    public void startsWith() {
        StartsWithFilter filter = (StartsWithFilter) FilterBuilder.startsWith(AttributeBuilder.build("foo", ""));
        assertEquals(forNativeFilter("(foo=*)"), newTranslator().createStartsWithExpression(filter, false));
        assertEquals(forNativeFilter("(!(foo=*))"), newTranslator().createStartsWithExpression(filter, true));

        filter = (StartsWithFilter) FilterBuilder.startsWith(AttributeBuilder.build("foo", "bar"));
        assertEquals(forNativeFilter("(foo=bar*)"), newTranslator().createStartsWithExpression(filter, false));
        assertEquals(forNativeFilter("(!(foo=bar*))"), newTranslator().createStartsWithExpression(filter, true));
    }

    @Test
    public void endsWith() {
        EndsWithFilter filter = (EndsWithFilter) FilterBuilder.endsWith(AttributeBuilder.build("foo", ""));
        assertEquals(forNativeFilter("(foo=*)"), newTranslator().createEndsWithExpression(filter, false));
        assertEquals(forNativeFilter("(!(foo=*))"), newTranslator().createEndsWithExpression(filter, true));

        filter = (EndsWithFilter) FilterBuilder.endsWith(AttributeBuilder.build("foo", "bar"));
        assertEquals(forNativeFilter("(foo=*bar)"), newTranslator().createEndsWithExpression(filter, false));
        assertEquals(forNativeFilter("(!(foo=*bar))"), newTranslator().createEndsWithExpression(filter, true));
    }

    @Test
    public void equals() {
        EqualsFilter filter = (EqualsFilter) FilterBuilder.equalTo(AttributeBuilder.build("foo"));
        assertNull(newTranslator().createEqualsExpression(filter, false));

        filter = (EqualsFilter) FilterBuilder.equalTo(AttributeBuilder.build("foo", ""));
        assertEquals(forNativeFilter("(foo=*)"), newTranslator().createEqualsExpression(filter, false));
        assertEquals(forNativeFilter("(!(foo=*))"), newTranslator().createEqualsExpression(filter, true));

        filter = (EqualsFilter) FilterBuilder.equalTo(AttributeBuilder.build("foo", "bar"));
        assertEquals(forNativeFilter("(foo=bar)"), newTranslator().createEqualsExpression(filter, false));
        assertEquals(forNativeFilter("(!(foo=bar))"), newTranslator().createEqualsExpression(filter, true));

        filter = (EqualsFilter) FilterBuilder.equalTo(AttributeBuilder.build("foo", "bar", "baz"));
        assertEquals(forNativeFilter("(&(foo=bar)(foo=baz))"), newTranslator().createEqualsExpression(filter, false));
        assertEquals(forNativeFilter("(!(&(foo=bar)(foo=baz)))"), newTranslator().createEqualsExpression(filter, true));
    }

    @Test
    public void equalsIgnoreCase() {
        EqualsIgnoreCaseFilter filter = (EqualsIgnoreCaseFilter) FilterBuilder.equalsIgnoreCase(AttributeBuilder.build(
                "foo", ""));
        assertEquals(forNativeFilter("(foo=*)"), newTranslator().createEqualsIgnoreCaseExpression(filter, false));
        assertEquals(forNativeFilter("(!(foo=*))"), newTranslator().createEqualsIgnoreCaseExpression(filter, true));

        filter = (EqualsIgnoreCaseFilter) FilterBuilder.equalsIgnoreCase(AttributeBuilder.build("foo", "bar"));
        assertEquals(forNativeFilter("(foo=bar)"), newTranslator().createEqualsIgnoreCaseExpression(filter, false));
        assertEquals(forNativeFilter("(!(foo=bar))"), newTranslator().createEqualsIgnoreCaseExpression(filter, true));
    }

    @Test
    public void greaterThan() {
        GreaterThanFilter filter = (GreaterThanFilter) FilterBuilder.greaterThan(AttributeBuilder.build("foo", 42));
        assertEquals(forNativeFilter("(!(foo<=42))"), newTranslator().createGreaterThanExpression(filter, false));
        assertEquals(forNativeFilter("(foo<=42)"), newTranslator().createGreaterThanExpression(filter, true));
    }

    @Test
    public void greaterThanOrEqual() {
        GreaterThanOrEqualFilter filter = (GreaterThanOrEqualFilter) FilterBuilder.greaterThanOrEqualTo(
                AttributeBuilder.build("foo", 42));
        assertEquals(forNativeFilter("(foo>=42)"), newTranslator().createGreaterThanOrEqualExpression(filter, false));
        assertEquals(forNativeFilter("(!(foo>=42))"), newTranslator().createGreaterThanOrEqualExpression(filter, true));
    }

    @Test
    public void lessThan() {
        LessThanFilter filter = (LessThanFilter) FilterBuilder.lessThan(AttributeBuilder.build("foo", 42));
        assertEquals(forNativeFilter("(!(foo>=42))"), newTranslator().createLessThanExpression(filter, false));
        assertEquals(forNativeFilter("(foo>=42)"), newTranslator().createLessThanExpression(filter, true));
    }

    @Test
    public void lessThanOrEqual() {
        LessThanOrEqualFilter filter = (LessThanOrEqualFilter) FilterBuilder.lessThanOrEqualTo(AttributeBuilder.build(
                "foo", 42));
        assertEquals(forNativeFilter("(foo<=42)"), newTranslator().createLessThanOrEqualExpression(filter, false));
        assertEquals(forNativeFilter("(!(foo<=42))"), newTranslator().createLessThanOrEqualExpression(filter, true));
    }

    @Test
    public void entryDN() {
        ContainsFilter contains = (ContainsFilter) FilterBuilder.contains(AttributeBuilder.build("entryDN",
                "dc=example,dc=com"));
        assertEquals(forEntryDN("dc=example,dc=com"), newTranslator().createContainsExpression(contains, false));

        StartsWithFilter startsWith = (StartsWithFilter) FilterBuilder.startsWith(AttributeBuilder.build("entryDN",
                "dc=example,dc=com"));
        assertEquals(forEntryDN("dc=example,dc=com"), newTranslator().createStartsWithExpression(startsWith, false));

        EndsWithFilter endsWith = (EndsWithFilter) FilterBuilder.endsWith(AttributeBuilder.build("entryDN",
                "dc=example,dc=com"));
        assertEquals(forEntryDN("dc=example,dc=com"), newTranslator().createEndsWithExpression(endsWith, false));

        EqualsFilter equals = (EqualsFilter) FilterBuilder.equalTo(AttributeBuilder.
                build("entryDN", "dc=example,dc=com"));
        assertEquals(forEntryDN("dc=example,dc=com"), newTranslator().createEqualsExpression(equals, false));

        ContainsAllValuesFilter containsAllValues = (ContainsAllValuesFilter) FilterBuilder.containsAllValues(
                AttributeBuilder.build("entryDN", "dc=example,dc=com"));
        assertEquals(forEntryDN("dc=example,dc=com"), newTranslator().createContainsAllValuesExpression(
                containsAllValues, false));

        containsAllValues = (ContainsAllValuesFilter) FilterBuilder.containsAllValues(AttributeBuilder.build("entryDN",
                "dc=example,dc=com", "o=Acme,dc=example,dc=com"));
        assertNull(newTranslator().createContainsAllValuesExpression(containsAllValues, false));
    }

    private static LdapFilterTranslator newTranslator() {
        LdapConfiguration config = LdapConnectorTestBase.newConfiguration();
        LdapConnection conn = new LdapConnection(config);
        return new LdapFilterTranslator(new LdapSchemaMapping(conn), ObjectClass.ACCOUNT);
    }
}
