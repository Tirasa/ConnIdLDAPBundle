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
package net.tirasa.connid.bundles.ldap.commons;

import java.util.Set;
import javax.naming.directory.Attributes;
import org.identityconnectors.common.StringUtil;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.objects.AttributeDelta;

public abstract class StatusManagement {

    private static final Log LOG = Log.getLog(StatusManagement.class);

    private static StatusManagement INSTANCE = null;

    /**
     * Implements this method to alter information given by input parameters in
     * order to implement a custom enable/disable behaviour.
     *
     * @param status enabled or not
     * @param attributes entity ldap attributes.
     */
    public abstract void setStatus(final boolean status, final Attributes attributes);

    /**
     * Implements this method to alter information given by input parameters in
     * order to implement a custom enable/disable behaviour.
     *
     * @param status enabled or not
     * @param modifications update delta attributes.
     */
    public abstract void setStatus(final boolean status, final Set<AttributeDelta> modifications);

    /**
     * Implement this method to retrieve user status from the given parameters.
     *
     * @param attributes entity ldap attributes.
     * @return TRUE if users is enable, FALS if disabled, null for no status found.
     */
    public abstract Boolean getStatus(final Attributes attributes);

    /**
     * Provide all the ldap attributes needed to know the entity status.
     *
     * @return set of ldap attributes to be added to the set of all the
     * attributes to get during searches.
     */
    public abstract Set<String> getOperationalAttributes();

    public static StatusManagement getInstance(String className) {
        if (INSTANCE == null || !INSTANCE.getClass().getName().equals(className)) {
            if (StringUtil.isNotBlank(className)) {
                try {
                    INSTANCE = (StatusManagement) Class.forName(className).getDeclaredConstructor().newInstance();
                } catch (Exception e) {
                    LOG.error(e, "Could not create instance of {0}", className);
                }
            }
            if (INSTANCE == null) {
                INSTANCE = new DefaultStatusManagement();
            }
        }

        return INSTANCE;
    }
}
