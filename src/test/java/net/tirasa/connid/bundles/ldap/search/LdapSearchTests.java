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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.api.ConnectorFacade;
import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.AttributeBuilder;
import org.identityconnectors.framework.common.objects.AttributeInfo;
import org.identityconnectors.framework.common.objects.AttributeInfoUtil;
import org.identityconnectors.framework.common.objects.AttributeUtil;
import org.identityconnectors.framework.common.objects.ConnectorObject;
import org.identityconnectors.framework.common.objects.Name;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.OperationOptions;
import org.identityconnectors.framework.common.objects.OperationOptionsBuilder;
import org.identityconnectors.framework.common.objects.OperationalAttributes;
import org.identityconnectors.framework.common.objects.QualifiedUid;
import org.identityconnectors.framework.common.objects.ResultsHandler;
import org.identityconnectors.framework.common.objects.Uid;
import org.identityconnectors.framework.common.objects.filter.Filter;
import org.identityconnectors.framework.common.objects.filter.FilterBuilder;
import net.tirasa.connid.bundles.ldap.LdapConfiguration;
import net.tirasa.connid.bundles.ldap.LdapConnection;
import net.tirasa.connid.bundles.ldap.LdapConnectorTestBase;
import net.tirasa.connid.bundles.ldap.schema.LdapSchemaMapping;

import org.identityconnectors.common.CollectionUtil;
import org.identityconnectors.framework.common.objects.SearchResult;
import org.identityconnectors.framework.spi.SearchResultsHandler;
import org.identityconnectors.test.common.TestHelpers;
import org.identityconnectors.test.common.ToListResultsHandler;
import org.junit.jupiter.api.Test;

public class LdapSearchTests extends LdapConnectorTestBase {

    // TODO operational attributes.
    // TODO LDAP directory attributes (entryDN, etc.).

    @Test
    public void ldapFilter() {
        LdapConnection conn = new LdapConnection(newConfiguration());

        LdapFilter filter = LdapFilter.forEntryDN(BUGS_BUNNY_DN);
        ToListResultsHandler handler = new ToListResultsHandler();
        new LdapSearch(conn, ObjectClass.ACCOUNT, filter, handler, new OperationOptionsBuilder().build()).execute();
        assertEquals(1, handler.getObjects().size());

        filter = filter.withNativeFilter("(foo=bar)");
        handler = new ToListResultsHandler();
        new LdapSearch(conn, ObjectClass.ACCOUNT, filter, handler, new OperationOptionsBuilder().build()).execute();
        assertTrue(handler.getObjects().isEmpty());
    }

    @Test
    public void ldapFilterWithNonExistingEntryDN() {
        LdapFilter filter = LdapFilter.forEntryDN("dc=foo,dc=bar");

        // VLV index.
        LdapConfiguration config = newConfiguration();
        config.setUseVlvControls(true);
        searchExpectingNoResult(config, filter, new OperationOptionsBuilder().build());

        // Simple paged results.
        config = newConfiguration();
        searchExpectingNoResult(config, filter, new OperationOptionsBuilder().setPageSize(25).build());

        // No paging.
        config = newConfiguration();
        searchExpectingNoResult(config, filter, new OperationOptionsBuilder().build());
    }

    @Test
    public void ldapFilterWithInvalidEntryDN() {
        LdapFilter filter = LdapFilter.forEntryDN("dc=foo,,");

        // VLV index.
        LdapConfiguration config = newConfiguration();
        config.setUseVlvControls(true);
        searchExpectingNoResult(config, filter, new OperationOptionsBuilder().build());

        // Simple paged results.
        config = newConfiguration();
        searchExpectingNoResult(config, filter, new OperationOptionsBuilder().setPageSize(25).build());

        // No paging.
        config = newConfiguration();
        searchExpectingNoResult(config, filter, new OperationOptionsBuilder().build());
    }

    private void searchExpectingNoResult(
            final LdapConfiguration config, final LdapFilter filter, final OperationOptions options) {

        LdapConnection conn = new LdapConnection(config);
        ToListResultsHandler handler = new ToListResultsHandler();
        // Should not fail with NameNotFoundException or InvalidNameException.
        new LdapSearch(conn, ObjectClass.ACCOUNT, filter, handler, options).execute();
        assertTrue(handler.getObjects().isEmpty());
    }

    @Test
    public void canCancelSearch() {
        // VLV Index.
        LdapConfiguration config = newConfiguration();
        config.setBaseContexts(ACME_DN, BIG_COMPANY_DN);
        config.setUseVlvControls(true);
        searchExpectingSingleResult(config, new OperationOptionsBuilder().build());

        // Simple paged results.
        config = newConfiguration();
        config.setBaseContexts(ACME_DN, BIG_COMPANY_DN);
        searchExpectingSingleResult(config, new OperationOptionsBuilder().setPageSize(25).build());

        // No paging.
        config = newConfiguration();
        config.setBaseContexts(ACME_DN, BIG_COMPANY_DN);
        searchExpectingSingleResult(config, new OperationOptionsBuilder().build());
    }

    private void searchExpectingSingleResult(final LdapConfiguration config, final OperationOptions options) {
        LdapConnection conn = new LdapConnection(config);
        FirstOnlyResultsHandler handler = new FirstOnlyResultsHandler();
        new LdapSearch(conn, ObjectClass.ACCOUNT, null, handler, options).execute();
        handler.assertSingleResult();
    }

    @Test
    public void simplePagedSearch() {
        LdapConfiguration config = newConfiguration();
        ConnectorFacade facade = newFacade(config);

        // read first page
        List<ConnectorObject> objects = TestHelpers.searchToList(
                facade, ObjectClass.ACCOUNT, null, new OperationOptionsBuilder().setPageSize(100).build());
        assertNotNull(getObjectByName(objects, BUGS_BUNNY_DN));
        assertNotNull(getObjectByName(objects, USER_0_DN));
        assertEquals(100, objects.size());

        // read all pages, being each page of 100 entries
        final OperationOptionsBuilder builder = new OperationOptionsBuilder().setPageSize(100);
        final String[] cookies = new String[1];
        final Integer[] count = new Integer[] { 0, 0 };
        do {
            count[0] = 0;

            if (cookies[0] != null) {
                builder.setPagedResultsCookie(cookies[0]);
            }

            new LdapSearch(new LdapConnection(config), ObjectClass.ACCOUNT, null, new SearchResultsHandler() {

                @Override
                public void handleResult(final SearchResult result) {
                    assertTrue(result.isAllResultsReturned());
                    cookies[0] = result.getPagedResultsCookie();
                }

                @Override
                public boolean handle(final ConnectorObject connectorObject) {
                    // counts entries per page
                    count[0]++;
                    // counts entries globally
                    count[1]++;
                    return true;
                }
            }, builder.build()).execute();

            if (cookies[0] != null) {
                assertEquals(100, count[0], 0);
            }
        } while (cookies[0] != null);

        // 2000 from BIG_COMPANY_DN, 4 from ACME_DN
        assertEquals(2000 + 5, count[1], 0);
    }

    @Test
    public void vlvIndexSearch() {
        LdapConfiguration config = newConfiguration();
        config.setBaseContexts(EXAMPLE_COM_DN);
        config.setUidAttribute("entryDN");
        config.setGidAttribute("entryDN");
        config.setUseVlvControls(true);
        ConnectorFacade facade = newFacade(config);

        List<ConnectorObject> objects = TestHelpers.searchToList(
                facade, ObjectClass.ACCOUNT, null, new OperationOptionsBuilder().setPageSize(1).build());
        assertNotNull(getObjectByName(objects, USER_0_DN));
        // 1000 is the default search size limit for OpenDJ.
        assertTrue(objects.size() > 1000);

        // OpenDJ-specific.
        OperationOptionsBuilder builder = new OperationOptionsBuilder().setAttributesToGet("debugsearchindex");
        FirstOnlyResultsHandler handler = new FirstOnlyResultsHandler();
        facade.search(ObjectClass.ACCOUNT, null, handler, builder.setPageSize(1).build());
        String debugsearch = handler.getSingleResult().
                getAttributeByName("debugsearchindex").getValue().get(0).toString();
        assertTrue(debugsearch.contains("vlv"));
    }

    public void defaultStrategy() {
        LdapConfiguration config = newConfiguration();
        ConnectorFacade facade = newFacade(config);

        final boolean[] isAllResultsReturned = new boolean[1];
        facade.search(ObjectClass.ACCOUNT, null, new org.identityconnectors.framework.spi.SearchResultsHandler() {

            @Override
            public void handleResult(final SearchResult result) {
                isAllResultsReturned[0] = result.isAllResultsReturned();
            }

            @Override
            public boolean handle(final ConnectorObject connectorObject) {
                return true;
            }
        }, null);

        // the search will exceed the maximum number of entries to return
        assertFalse(isAllResultsReturned[0]);
    }

    @Test
    public void withFilter() {
        ConnectorFacade facade = newFacade();
        ConnectorObject bunny = searchByAttribute(facade, ObjectClass.ACCOUNT, new Name(BUGS_BUNNY_DN));
        assertEquals(BUGS_BUNNY_DN, bunny.getName().getNameValue());
    }

    @Test
    public void withFilterByBinaryAttribute() {
        ConnectorFacade facade = newFacade();
        ConnectorObject bunny = searchByAttribute(facade, ObjectClass.ACCOUNT, new Name(BUGS_BUNNY_DN));

        byte[] photo = { -4, -3, -2, -1, 0, 1, 2, 3, 63, 127 };
        Attribute photoAttr = AttributeBuilder.build("jpegPhoto", photo);
        Uid newUid = facade.addAttributeValues(
                ObjectClass.ACCOUNT, bunny.getUid(), Collections.singleton(photoAttr), null);

        ConnectorObject bunnyWithPhoto = searchByAttribute(facade, ObjectClass.ACCOUNT, photoAttr, "jpegPhoto");
        assertEquals(newUid, bunnyWithPhoto.getUid());
    }

    @Test
    public void attributesToGet() {
        ConnectorFacade facade = newFacade();
        ConnectorObject object = searchByAttribute(
                facade, ObjectClass.ACCOUNT, new Name(USER_0_DN), "employeeNumber", "telephoneNumber");

        Set<Attribute> attrs = CollectionUtil.newSet(object.getAttributes());
        assertTrue(attrs.remove(AttributeUtil.find(Uid.NAME, attrs)));
        assertTrue(attrs.remove(AttributeUtil.find(Name.NAME, attrs)));
        assertTrue(attrs.remove(AttributeUtil.find("employeeNumber", attrs)));
        assertTrue(attrs.remove(AttributeUtil.find("telephoneNumber", attrs)));

        assertTrue(attrs.isEmpty());
    }

    @Test
    public void attributesReturnedByDefaultWithNoValueAreNotReturned() {
        LdapConfiguration config = newConfiguration(true);
        ConnectorFacade facade = newFacade(config);
        AttributeInfo attr = AttributeInfoUtil.find("givenName", facade.schema().findObjectClassInfo(
                ObjectClass.ACCOUNT_NAME).getAttributeInfo());
        assertTrue(attr.isReturnedByDefault());

        ConnectorObject object = searchByAttribute(facade, ObjectClass.ACCOUNT, new Name(BUGS_BUNNY_DN));
        assertNull(object.getAttributeByName("givenName"));
    }

    @Test
    public void attributesToGetNotPresentInEntryAreEmpty() {
        ConnectorFacade facade = newFacade();
        ConnectorObject object = searchByAttribute(facade, ObjectClass.ACCOUNT, new Name(BUGS_BUNNY_DN),
                "employeeNumber");

        assertTrue(object.getAttributeByName("employeeNumber").getValue().isEmpty());
    }

    @Test
    public void scope() {
        ConnectorFacade facade = newFacade();
        // Find an organization to pass in OP_CONTAINER.
        ObjectClass oclass = new ObjectClass("organization");
        ConnectorObject organization = searchByAttribute(facade, oclass, new Name(BIG_COMPANY_DN));

        // There are no accounts directly under the organization...
        OperationOptionsBuilder optionsBuilder = new OperationOptionsBuilder();
        optionsBuilder.setScope(OperationOptions.SCOPE_ONE_LEVEL);
        optionsBuilder.setContainer(new QualifiedUid(oclass, organization.getUid()));
        optionsBuilder.setPageSize(100);
        List<ConnectorObject> objects = TestHelpers.searchToList(
                facade, ObjectClass.ACCOUNT, null, optionsBuilder.build());
        assertTrue(objects.isEmpty());

        // ... but there are some in the organization subtree.
        optionsBuilder.setScope(OperationOptions.SCOPE_SUBTREE);
        objects = TestHelpers.searchToList(facade, ObjectClass.ACCOUNT, null, optionsBuilder.build());
        assertFalse(objects.isEmpty());
    }

    @Test
    public void configurableUserScope() {
        LdapConfiguration configuration = newConfiguration();
        configuration.setUserSearchScope("object");
        ConnectorFacade facade = newFacade(configuration);

        // Find an organization to pass in OP_CONTAINER.
        ObjectClass oclass = new ObjectClass("organization");
        ConnectorObject organization = searchByAttribute(facade, oclass, new Name(ACME_DN));

        // Prepare options
        OperationOptionsBuilder optionsBuilder = new OperationOptionsBuilder();
        optionsBuilder.setContainer(new QualifiedUid(oclass, organization.getUid()));
        optionsBuilder.setPageSize(100);
        OperationOptions options = optionsBuilder.build();

        // We can get bugs bunny with an 'object' search by DN
        ConnectorObject bugsBunny = searchByAttribute(facade, ObjectClass.ACCOUNT, new Name(BUGS_BUNNY_DN));
        assertNotNull(bugsBunny);

        // Reconfigure for 'onelevel' search
        configuration.setUserSearchScope("onelevel");
        configuration.setAccountSearchFilter("(uid=" + BUGS_BUNNY_UID + ")");
        facade = newFacade(configuration);

        // Bugs Bunny doesn't exist directly under the organisation..
        List<ConnectorObject> objects = TestHelpers.searchToList(
                facade, ObjectClass.ACCOUNT, null, options);
        assertTrue(objects.isEmpty());

        // Reconfigure for 'subtree' search
        configuration.setUserSearchScope("subtree");
        facade = newFacade(configuration);

        // ... but does in the organisation subtree
        objects = TestHelpers.searchToList(facade, ObjectClass.ACCOUNT, null, options);
        assertFalse(objects.isEmpty());
    }

    @Test
    public void configurableGroupScope() {
        LdapConfiguration configuration = newConfiguration();
        configuration.setGroupSearchScope("object");
        ConnectorFacade facade = newFacade(configuration);

        // Find an organization to pass in OP_CONTAINER.
        ObjectClass oclass = new ObjectClass("organization");
        ConnectorObject organization = searchByAttribute(facade, oclass, new Name(ACME_DN));

        // Prepare options
        OperationOptionsBuilder optionsBuilder = new OperationOptionsBuilder();
        optionsBuilder.setContainer(new QualifiedUid(oclass, organization.getUid()));
        optionsBuilder.setPageSize(100);
        OperationOptions options = optionsBuilder.build();

        // We can get 'unique bugs and friends' with an 'object' search by DN
        ConnectorObject uniqueBugsAndFriends = searchByAttribute(
                facade, ObjectClass.GROUP, new Name(UNIQUE_BUGS_AND_FRIENDS_DN));
        assertNotNull(uniqueBugsAndFriends);

        // Reconfigure for 'onelevel' search
        configuration.setGroupSearchScope("onelevel");
        configuration.setGroupSearchFilter("(cn=" + UNIQUE_BUGS_AND_FRIENDS_CN + ")");
        facade = newFacade(configuration);

        // Bugs Bunny doesn't exist directly under the organisation..
        List<ConnectorObject> objects = TestHelpers.searchToList(
                facade, ObjectClass.GROUP, null, options);
        assertTrue(objects.isEmpty());

        // Reconfigure for 'subtree' search
        configuration.setGroupSearchScope("subtree");
        facade = newFacade(configuration);

        // ... but does in the organisation subtree
        objects = TestHelpers.searchToList(facade, ObjectClass.GROUP, null, options);
        assertFalse(objects.isEmpty());
    }

    @Test
    public void configurableAnyObjectScope() {
        LdapConfiguration configuration = newConfiguration();
        configuration.setAnyObjectSearchScope("object");
        configuration.setAnyObjectClasses("top", "organization");
        ConnectorFacade facade = newFacade(configuration);

        // Find an organization to pass in OP_CONTAINER.
        ObjectClass oclass = new ObjectClass("organization");
        ConnectorObject organization = searchByAttribute(facade, oclass, new Name(ACME_DN));

        // Prepare options
        OperationOptionsBuilder optionsBuilder = new OperationOptionsBuilder();
        optionsBuilder.setContainer(new QualifiedUid(oclass, organization.getUid()));
        optionsBuilder.setPageSize(100);
        OperationOptions options = optionsBuilder.build();

        // Set up for 'device' search
        configuration.setAnyObjectClasses("top", "device");
        facade = newFacade(configuration);

        // We can get the 'carrot laptop' device with an 'object' search by DN
        ConnectorObject carrotLaptop = searchByAttribute(
                facade, LdapSchemaMapping.ANY_OBJECT_CLASS, new Name(CARROT_LAPTOP_DN));
        assertNotNull(carrotLaptop);

        // Reconfigure for 'onelevel' search
        configuration.setAnyObjectSearchScope("onelevel");
        configuration.setAnyObjectSearchFilter("(cn=" + CARROT_LAPTOP_CN + ")");
        facade = newFacade(configuration);

        // 'carrot laptop'' doesn't exist directly under the organisation..
        List<ConnectorObject> objects = TestHelpers.searchToList(
                facade, LdapSchemaMapping.ANY_OBJECT_CLASS, null, options);
        assertTrue(objects.isEmpty());

        // Reconfigure for 'subtree' search
        configuration.setAnyObjectSearchScope("subtree");
        facade = newFacade(configuration);

        // ... but does in the organisation subtree
        objects = TestHelpers.searchToList(facade, LdapSchemaMapping.ANY_OBJECT_CLASS, null, options);
        assertFalse(objects.isEmpty());
    }

    @Test
    public void accountSearchFilter() {
        ConnectorFacade facade = newFacade();
        // Find an organization to pass in OP_CONTAINER.
        ObjectClass oclass = new ObjectClass("organization");
        ConnectorObject organization = searchByAttribute(facade, oclass, new Name(ACME_DN));

        // First just check that there really are some users.
        OperationOptionsBuilder optionsBuilder = new OperationOptionsBuilder();
        optionsBuilder.setScope(OperationOptions.SCOPE_SUBTREE);
        optionsBuilder.setContainer(new QualifiedUid(oclass, organization.getUid()));
        List<ConnectorObject> objects = TestHelpers.searchToList(
                facade, ObjectClass.ACCOUNT, null, optionsBuilder.build());
        assertNotNull(getObjectByName(objects, BUGS_BUNNY_DN));
        assertNotNull(getObjectByName(objects, ELMER_FUDD_DN));

        LdapConfiguration config = newConfiguration();
        config.setAccountSearchFilter("(uid=" + BUGS_BUNNY_UID + ")");
        facade = newFacade(config);
        objects = TestHelpers.searchToList(facade, ObjectClass.ACCOUNT, null, optionsBuilder.build());
        assertEquals(1, objects.size());
        assertNotNull(getObjectByName(objects, BUGS_BUNNY_DN));
    }

    @Test
    public void accountSearchFilterOnlyAppliesToAccounts() {
        LdapConfiguration config = newConfiguration();
        config.setAccountSearchFilter("(cn=foobarbaz)");
        ConnectorFacade facade = newFacade(config);

        // If the (cn=foobarbaz) filter above applied, the search would return nothing.
        assertNotNull(searchByAttribute(facade, new ObjectClass("organization"), new Name(ACME_DN)));
    }

    @Test
    public void missingParenthesesAddedToAccountSearchFilter() {
        LdapConfiguration config = newConfiguration();
        config.setAccountSearchFilter("uid=" + BUGS_BUNNY_UID); // No parentheses enclosing the filter.
        ConnectorFacade facade = newFacade(config);

        // If parentheses were not added, the search would fail.
        assertNotNull(searchByAttribute(facade, ObjectClass.ACCOUNT, new Name(BUGS_BUNNY_DN)));
    }

    @Test
    public void groupSearchFilter() {
        ConnectorFacade facade = newFacade();
        // Find an organization to pass in OP_CONTAINER.
        ObjectClass oclass = new ObjectClass("organization");
        ConnectorObject organization = searchByAttribute(facade, oclass, new Name(ACME_DN));

        // First just check that there really are some users.
        OperationOptionsBuilder optionsBuilder = new OperationOptionsBuilder();
        optionsBuilder.setScope(OperationOptions.SCOPE_SUBTREE);
        optionsBuilder.setContainer(new QualifiedUid(oclass, organization.getUid()));
        List<ConnectorObject> objects =
                TestHelpers.searchToList(facade, ObjectClass.GROUP, null, optionsBuilder.build());
        assertNotNull(getObjectByName(objects, UNIQUE_BUGS_AND_FRIENDS_DN));
        assertNotNull(getObjectByName(objects, UNIQUE_EMPTY_GROUP_DN));
        assertNotNull(getObjectByName(objects, UNIQUE_EXTERNAL_PEERS_DN));

        LdapConfiguration config = newConfiguration();
        config.setGroupSearchFilter("(cn=" + UNIQUE_BUGS_AND_FRIENDS_CN + ")");
        facade = newFacade(config);
        objects = TestHelpers.searchToList(facade, ObjectClass.GROUP, null, optionsBuilder.build());
        assertEquals(1, objects.size());
        assertNotNull(getObjectByName(objects, UNIQUE_BUGS_AND_FRIENDS_DN));
    }

    @Test
    public void groupsSearchFilterOnlyAppliesToGroups() {
        LdapConfiguration config = newConfiguration();
        config.setGroupSearchFilter("(cn=foobarbaz)");
        ConnectorFacade facade = newFacade(config);

        // If the (cn=foobarbaz) filter above applied, the search would return nothing.
        assertNotNull(searchByAttribute(facade, new ObjectClass("organization"), new Name(ACME_DN)));
    }

    @Test
    public void missingParenthesesAddedToGroupSearchFilter() {
        LdapConfiguration config = newConfiguration();
        config.setGroupSearchFilter("cn=" + UNIQUE_BUGS_AND_FRIENDS_CN); // No parentheses enclosing the filter.
        ConnectorFacade facade = newFacade(config);

        // If parentheses were not added, the search would fail.
        assertNotNull(searchByAttribute(facade, ObjectClass.GROUP, new Name(UNIQUE_BUGS_AND_FRIENDS_DN)));
    }

    @Test
    public void anyObjectSearchFilter() {
        LdapConfiguration configuration = newConfiguration();
        configuration.setAnyObjectClasses("top", "organization");
        ConnectorFacade facade = newFacade(configuration);
        // Find an organization to pass in OP_CONTAINER.
        ObjectClass oclass = new ObjectClass("organization");
        ConnectorObject organization = searchByAttribute(facade, oclass, new Name(ACME_DN));

        OperationOptionsBuilder optionsBuilder = new OperationOptionsBuilder();
        optionsBuilder.setScope(OperationOptions.SCOPE_SUBTREE);
        optionsBuilder.setContainer(new QualifiedUid(oclass, organization.getUid()));

        // First just check that there really are some anyObjects (devices in this case).
        configuration.setAnyObjectClasses("top", "device");
        configuration.setAnyObjectNameAttributes("cn");
        facade = newFacade(configuration);
        List<ConnectorObject> objects = TestHelpers.searchToList(
                facade, LdapSchemaMapping.ANY_OBJECT_CLASS, null, optionsBuilder.build());
        assertNotNull(getObjectByName(objects, CARROT_LAPTOP_DN));

        // Test the anyObject search filter
        configuration = newConfiguration();
        configuration.setAnyObjectSearchFilter("(cn=" + CARROT_LAPTOP_CN + ")");
        configuration.setAnyObjectClasses("top", "device");
        facade = newFacade(configuration);
        objects = TestHelpers.searchToList(facade, LdapSchemaMapping.ANY_OBJECT_CLASS, null, optionsBuilder.build());
        assertEquals(1, objects.size());
        assertNotNull(getObjectByName(objects, CARROT_LAPTOP_DN));
    }

    @Test
    public void anyObjectSearchFilterOnlyAppliesToAnyObjects() {
        LdapConfiguration config = newConfiguration();
        config.setAnyObjectSearchFilter("(cn=foobarbaz)");
        ConnectorFacade facade = newFacade(config);
        ConnectorObject bugsBunny = searchByAttribute(facade, ObjectClass.ACCOUNT, new Name(BUGS_BUNNY_DN));

        // If the (cn=foobarbaz) filter above applied, the search would return nothing.
        assertNotNull(bugsBunny);
    }

    @Test
    public void missingParenthesesAddedToAnyObjectSearchFilter() {
        LdapConfiguration config = newConfiguration();
        config.setAnyObjectSearchFilter("cn=" + CARROT_LAPTOP_CN); // No parentheses enclosing the filter.
        config.setAnyObjectClasses("top", "device");
        ConnectorFacade facade = newFacade(config);

        // If parentheses were not added, the search would fail.
        assertNotNull(searchByAttribute(facade, LdapSchemaMapping.ANY_OBJECT_CLASS, new Name(CARROT_LAPTOP_DN)));
    }

    @Test
    public void multipleBaseDNs() {
        ConnectorFacade facade = newFacade();

        // This should find accounts from both base DNs.
        List<ConnectorObject> objects = TestHelpers.searchToList(
                facade, ObjectClass.ACCOUNT, null, new OperationOptionsBuilder().setPageSize(1000).build());
        assertNotNull(getObjectByName(objects, BUGS_BUNNY_DN));
        assertNotNull(getObjectByName(objects, USER_0_DN));
    }

    @Test
    public void uidAttributeCn() {
        LdapConfiguration config = newConfiguration();
        assertFalse(config.getUidAttribute().equalsIgnoreCase("cn"));
        config.setUidAttribute("cn");
        config.setGidAttribute("cn");
        ConnectorFacade facade = newFacade(config);

        ConnectorObject bunny = searchByAttribute(facade, ObjectClass.ACCOUNT, new Uid(BUGS_BUNNY_CN));
        assertEquals(BUGS_BUNNY_DN, bunny.getName().getNameValue());
    }

    @Test
    public void uidAttributeEntryDN() {
        LdapConfiguration config = newConfiguration();
        assertFalse(config.getUidAttribute().equalsIgnoreCase("entryDN"));
        config.setUidAttribute("entryDN");
        config.setGidAttribute("entryDN");
        ConnectorFacade facade = newFacade(config);

        ConnectorObject bunny = searchByAttribute(facade, ObjectClass.ACCOUNT, new Uid(BUGS_BUNNY_DN));
        assertEquals(BUGS_BUNNY_DN, bunny.getName().getNameValue());
    }

    @Test
    public void searchArbitraryObjectClass() {
        ConnectorFacade facade = newFacade();

        // Simplest: try w/o filter.
        List<ConnectorObject> objects = TestHelpers.searchToList(facade, new ObjectClass("country"), null, null);
        ConnectorObject czechRep = getObjectByName(objects, CZECH_REPUBLIC_DN);
        assertNotNull(czechRep);

        // Try with a name filter and options.
        OperationOptionsBuilder builder = new OperationOptionsBuilder().setAttributesToGet("c");

        Filter filter = FilterBuilder.equalTo(AttributeBuilder.build(Name.NAME, CZECH_REPUBLIC_DN));
        objects = TestHelpers.searchToList(facade, new ObjectClass("country"), filter, builder.build());
        czechRep = getObjectByName(objects, CZECH_REPUBLIC_DN);
        assertEquals(CZECH_REPUBLIC_C, AttributeUtil.getAsStringValue(czechRep.getAttributeByName("c")));

        filter = FilterBuilder.equalsIgnoreCase(AttributeBuilder.build(Name.NAME, CZECH_REPUBLIC_DN));
        objects = TestHelpers.searchToList(facade, new ObjectClass("country"), filter, builder.build());
        czechRep = getObjectByName(objects, CZECH_REPUBLIC_DN);
        assertEquals(CZECH_REPUBLIC_C, AttributeUtil.getAsStringValue(czechRep.getAttributeByName("c")));
    }

    @Test
    public void cannotReturnPasswordFromSearch() {
        ConnectorFacade facade = newFacade();
        ConnectorObject bunny = searchByAttribute(facade, ObjectClass.ACCOUNT, new Name(BUGS_BUNNY_DN),
                OperationalAttributes.PASSWORD_NAME);
        GuardedString password =
                (GuardedString) bunny.getAttributeByName(OperationalAttributes.PASSWORD_NAME).getValue().get(0);
        password.access(clearChars -> assertEquals(0, clearChars.length));
    }

    @Test
    public void returnPasswordFromSearch() {
        LdapConfiguration config = newConfiguration();
        config.setRetrievePasswordsWithSearch(true);
        ConnectorFacade facade = newFacade(config);
        ConnectorObject bunny = searchByAttribute(facade, ObjectClass.ACCOUNT, new Name(BUGS_BUNNY_DN),
                OperationalAttributes.PASSWORD_NAME);
        GuardedString password =
                (GuardedString) bunny.getAttributeByName(OperationalAttributes.PASSWORD_NAME).getValue().get(0);
        password.access(clearChars -> assertTrue(clearChars.length > 0));
    }

    private static ConnectorObject getObjectByName(final List<ConnectorObject> objects, final String name) {
        for (ConnectorObject object : objects) {
            if (name.equals(object.getName().getNameValue())) {
                return object;
            }
        }
        return null;
    }

    private static final class FirstOnlyResultsHandler implements ResultsHandler {

        private final List<ConnectorObject> objects = new ArrayList<>();

        @Override
        public boolean handle(final ConnectorObject obj) {
            objects.add(obj);
            return false; // We only want the first one.
        }

        public void assertSingleResult() {
            assertEquals(1, objects.size());
        }

        public ConnectorObject getSingleResult() {
            return objects.get(0);
        }
    }
}
