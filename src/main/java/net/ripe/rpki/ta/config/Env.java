package net.ripe.rpki.ta.config;

/*-
 * ========================LICENSE_START=================================
 * RIPE NCC Trust Anchor
 * -
 * Copyright (C) 2017 RIPE NCC
 * -
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 * 
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 
 * 3. Neither the name of the RIPE NCC nor the names of its contributors
 *    may be used to endorse or promote products derived from this software without
 *    specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * =========================LICENSE_END==================================
 */


import net.ripe.rpki.ta.BadOptions;
import org.joda.time.Period;

import javax.security.auth.x500.X500Principal;
import java.net.URI;

public class Env {

    public static Config config(String envName) throws BadOptions {
        if (envName == null || "local".equals(envName)) {
            return local();
        }
        if ("dev".equals(envName)) {
            return dev();
        }
        if ("prepdev".equals(envName)) {
            return prepdev();
        }
        if ("production".equals(envName)) {
            return production();
        }
        throw new BadOptions("Unknown environment name: " + envName);
    }

    public static Config production() {
        final Config config = new Config();
        nCipherConf(config);
        config.setPersistentStorageDir("/export/bad/ta-ca/data/");
        config.setMinimumValidityPeriod(Period.months(1));
        config.setUpdatePeriod(Period.months(3));
        config.setTrustAnchorName(new X500Principal("CN=ripe-ncc-ta"));
        config.setTaCertificatePublicationUri(URI.create("rsync://rpki.ripe.net/ta/"));
        config.setTaProductsPublicationUri(URI.create("rsync://rpki.ripe.net/repository/"));
        config.setNotificationUri(URI.create("https://rrdp.ripe.net/notification.xml"));
        return config;
    }

    public static Config dev() {
        final Config config = testConfig();
        config.setTaCertificatePublicationUri(URI.create("rsync://rpki.dev.ripe.net/ta/"));
        config.setTaProductsPublicationUri(URI.create("rsync://rpki.dev.ripe.net/repository/"));
        return config;
    }

    public static Config prepdev() {
        final Config config = testConfig();
//        nCipherConf(config);
        config.setPersistentStorageDir("/export/bad/ta-ca/data/");
        config.setTaCertificatePublicationUri(URI.create("rsync://rpki.prepdev.ripe.net/ta/"));
        config.setTaProductsPublicationUri(URI.create("rsync://rpki.prepdev.ripe.net/repository/"));
//        config.setNotificationUri(URI.create("http://pub-server.elasticbeanstalk.com/notification.xml"));
        return config;
    }

    public static Config local() {
        final Config config = testConfig();
        config.setTaCertificatePublicationUri(URI.create("rsync://localhost:10873/ta/"));
        config.setTaProductsPublicationUri(URI.create("rsync://localhost:10873/online/"));
        return config;
    }

    private static Config testConfig() {
        final Config config = new Config();
        sunRsaConf(config);
        config.setPersistentStorageDir("/export/bad/certification/ta/data");
        config.setMinimumValidityPeriod(Period.months(1));
        config.setUpdatePeriod(Period.months(3));
        config.setTrustAnchorName(new X500Principal("CN=RIPE-NCC-TA-TEST"));
        config.setNotificationUri(URI.create("https://rrdp.ripe.net/notification.xml"));
        return config;
    }

    private static void nCipherConf(Config config) {
        config.setSignatureProvider("nCipherKM");
        config.setKeystoreProvider("nCipherKM");
        config.setKeypairGeneratorProvider("nCipherKM");
        config.setKeystoreType("ncipher.sworld");
    }

    private static void sunRsaConf(Config config) {
        config.setSignatureProvider("SunRsaSign");
        config.setKeystoreProvider("SUN");
        config.setKeypairGeneratorProvider("SunRsaSign");
        config.setKeystoreType("JKS");
    }
}
