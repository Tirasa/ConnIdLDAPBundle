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

import static net.tirasa.connid.bundles.ldap.commons.LdapEntry.isDNAttribute;
import static net.tirasa.connid.bundles.ldap.commons.LdapUtil.escapeAttrValue;

import java.util.List;

import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.filter.AbstractFilterTranslator;
import org.identityconnectors.framework.common.objects.filter.AttributeFilter;
import org.identityconnectors.framework.common.objects.filter.ContainsAllValuesFilter;
import org.identityconnectors.framework.common.objects.filter.ContainsFilter;
import org.identityconnectors.framework.common.objects.filter.EndsWithFilter;
import org.identityconnectors.framework.common.objects.filter.EqualsFilter;
import org.identityconnectors.framework.common.objects.filter.GreaterThanFilter;
import org.identityconnectors.framework.common.objects.filter.GreaterThanOrEqualFilter;
import org.identityconnectors.framework.common.objects.filter.LessThanFilter;
import org.identityconnectors.framework.common.objects.filter.LessThanOrEqualFilter;
import org.identityconnectors.framework.common.objects.filter.SingleValueAttributeFilter;
import org.identityconnectors.framework.common.objects.filter.StartsWithFilter;
import net.tirasa.connid.bundles.ldap.schema.LdapSchema;
import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.AttributeBuilder;
import org.identityconnectors.framework.common.objects.filter.EqualsIgnoreCaseFilter;

public class LdapFilterTranslator extends AbstractFilterTranslator<LdapFilter> {

    // Notes:
    //
    // - The connector EqualsFilter matches an attribute and
    // its values exactly, so we try to do the same.
    //
    // - The note in the openconnectors LDAP connector claiming that
    // "(!(a > X)) is only the same as (a <= X) if every object has a value of a"
    // seems incorrect. For an object not having an a attribute, (a <= X) will
    // be Undefined (cf. RFC 4511, section 4.5.1.7). But (a > X) would be Undefined
    // too, and so would be (!(a > X)).
    protected final LdapSchema mapping;

    protected final ObjectClass objectClass;

    public LdapFilterTranslator(LdapSchema mapping, ObjectClass objectClass) {
        this.mapping = mapping;
        this.objectClass = objectClass;
    }

    @Override
    public LdapFilter createAndExpression(LdapFilter leftExpression, LdapFilter rightExpression) {
        return leftExpression.and(rightExpression);
    }

    @Override
    public LdapFilter createOrExpression(LdapFilter leftExpression, LdapFilter rightExpression) {
        return leftExpression.or(rightExpression);
    }

    @Override
    public LdapFilter createContainsExpression(ContainsFilter filter, boolean not) {
        String attrName = mapping.getLdapAttribute(objectClass, filter.
                getAttribute());
        if (attrName == null) {
            return null;
        }
        if (isDNAttribute(attrName)) {
            return LdapFilter.forEntryDN(filter.getValue());
        }

        StringBuilder builder = createBuilder(not);
        builder.append(attrName);
        builder.append('=');
        builder.append('*');
        if (escapeAttrValue(filter.getValue(), builder)) {
            builder.append('*');
        }
        return finishBuilder(builder);
    }

    @Override
    public LdapFilter createEndsWithExpression(EndsWithFilter filter, boolean not) {
        String attrName = mapping.getLdapAttribute(objectClass, filter.
                getAttribute());
        if (attrName == null) {
            return null;
        }
        if (isDNAttribute(attrName)) {
            return LdapFilter.forEntryDN(filter.getValue());
        }

        StringBuilder builder = createBuilder(not);
        builder.append(attrName);
        builder.append('=');
        builder.append('*');
        escapeAttrValue(filter.getValue(), builder);
        return finishBuilder(builder);
    }

    @Override
    public LdapFilter createEqualsExpression(EqualsFilter filter, boolean not) {
        // XXX is there a way in LDAP to test that the values of an attribute
        // exactly match a given list of values?
        return createContainsAllValuesFilter(filter, not);
    }

    @Override
    protected LdapFilter createEqualsIgnoreCaseExpression(EqualsIgnoreCaseFilter filter, boolean not) {
        // LDAP is generally case-insensitive, reverting to EqualsFilter
        Attribute attr = filter.getValue() == null
                ? AttributeBuilder.build(filter.getName())
                : AttributeBuilder.build(filter.getName(), filter.getValue());
        return createEqualsExpression(new EqualsFilter(attr), not);
    }

    @Override
    public LdapFilter createGreaterThanExpression(GreaterThanFilter filter, boolean not) {
        return createSingleValueFilter("<=", filter, !not);
    }

    @Override
    public LdapFilter createGreaterThanOrEqualExpression(GreaterThanOrEqualFilter filter, boolean not) {
        return createSingleValueFilter(">=", filter, not);
    }

    @Override
    public LdapFilter createLessThanExpression(LessThanFilter filter, boolean not) {
        return createSingleValueFilter(">=", filter, !not);
    }

    @Override
    public LdapFilter createLessThanOrEqualExpression(LessThanOrEqualFilter filter, boolean not) {
        return createSingleValueFilter("<=", filter, not);
    }

    @Override
    public LdapFilter createStartsWithExpression(StartsWithFilter filter, boolean not) {
        String attrName = mapping.getLdapAttribute(objectClass, filter.
                getAttribute());
        if (attrName == null) {
            return null;
        }
        if (isDNAttribute(attrName)) {
            return LdapFilter.forEntryDN(filter.getValue());
        }

        StringBuilder builder = createBuilder(not);
        builder.append(attrName);
        builder.append('=');
        escapeAttrValue(filter.getValue(), builder);
        builder.append('*');
        return finishBuilder(builder);
    }

    @Override
    public LdapFilter createContainsAllValuesExpression(ContainsAllValuesFilter filter, boolean not) {
        return createContainsAllValuesFilter(filter, not);
    }

    protected LdapFilter createSingleValueFilter(String type, SingleValueAttributeFilter filter, boolean not) {
        String attrName = mapping.getLdapAttribute(objectClass, filter.
                getAttribute());
        if (attrName == null) {
            return null;
        }
        if (isDNAttribute(attrName)) {
            return LdapFilter.forEntryDN(filter.getValue().toString());
        }

        StringBuilder builder = createBuilder(not);
        Object value = filter.getValue();
        addSimpleFilter(attrName, type, value, builder);
        return finishBuilder(builder);
    }

    protected void addSimpleFilter(String ldapAttr, String type, Object value, StringBuilder toBuilder) {
        toBuilder.append(ldapAttr);
        toBuilder.append(type);
        if (!escapeAttrValue(value, toBuilder)) {
            toBuilder.append('*');
        }
    }

    protected LdapFilter createContainsAllValuesFilter(AttributeFilter filter, boolean not) {
        String attrName = mapping.getLdapAttribute(objectClass, filter.
                getAttribute());
        if (attrName == null) {
            return null;
        }
        List<Object> values = filter.getAttribute().getValue();
        if (values == null) {
            return null;
        }
        StringBuilder builder;
        switch (values.size()) {
            case 0:
                return null;
            case 1:
                Object single = values.get(0);
                if (single == null) {
                    return null;
                }
                if (isDNAttribute(attrName)) {
                    return LdapFilter.forEntryDN(single.toString());
                }
                builder = createBuilder(not);
                addSimpleFilter(attrName, "=", values.get(0), builder);
                return finishBuilder(builder);
            default:
                if (isDNAttribute(attrName)) {
                    return null; // Because the DN is single-valued.
                }
                builder = createBuilder(not);
                boolean hasValue = false;
                builder.append('&');
                for (Object value : values) {
                    if (value != null) {
                        hasValue = true;
                        builder.append('(');
                        addSimpleFilter(attrName, "=", value, builder);
                        builder.append(')');
                    }
                }
                if (!hasValue) {
                    return null;
                }
                return finishBuilder(builder);
        }
    }

    protected StringBuilder createBuilder(boolean not) {
        return new StringBuilder(not ? "(!(" : "(");
    }

    protected LdapFilter finishBuilder(StringBuilder builder) {
        boolean not = builder.charAt(0) == '(' && builder.charAt(1) == '!';
        builder.append(not ? "))" : ")");
        return LdapFilter.forNativeFilter(builder.toString());
    }
}
