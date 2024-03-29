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
package net.tirasa.connid.bundles.ldap;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactorySpi;
import javax.net.ssl.X509TrustManager;

/**
 * A trust provider which blindly trusts any certificate.
 * This saves from having to generate the certificate, import it into a trust file, specify the file, etc.
 *
 * Inspired by <a href="http://www.howardism.org/Technical/Java/SelfSignedCerts.html">
 * http://www.howardism.org/Technical/Java/SelfSignedCerts.html</a>.
 */
public class BlindTrustProvider extends Provider {

    private static final long serialVersionUID = 6857872576693926685L;

    private static final String ID = "BlindTrustProvider";

    private static final String ALGORITHM = "Blind";

    public static final void register() {
        if (Security.getProvider(ID) == null) {
            Security.insertProviderAt(new BlindTrustProvider(), 1);
            Security.setProperty("ssl.TrustManagerFactory.algorithm", ALGORITHM);
        }
    }

    @SuppressWarnings("deprecation")
    public BlindTrustProvider() {
        super(ID, 1.0, ID);
        put("TrustManagerFactory." + ALGORITHM, BlindTrustManagerFactory.class.getName());
    }

    public static final class BlindTrustManagerFactory extends TrustManagerFactorySpi {

        @Override
        protected TrustManager[] engineGetTrustManagers() {
            return new TrustManager[] { new BlindTrustManager() };
        }

        @Override
        protected void engineInit(final KeyStore ks) throws KeyStoreException {
        }

        @Override
        protected void engineInit(final ManagerFactoryParameters spec) throws InvalidAlgorithmParameterException {
        }
    }

    public static final class BlindTrustManager implements X509TrustManager {

        @Override
        public void checkClientTrusted(final X509Certificate[] chain, final String authType)
                throws CertificateException {
        }

        @Override
        public void checkServerTrusted(final X509Certificate[] chain, final String authType)
                throws CertificateException {
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return null;
        }
    }
}
