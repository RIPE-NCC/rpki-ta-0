/**
 * Copyright © 2017, RIPE NCC
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the <organization> nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
package net.ripe.rpki.ta.config;



import net.ripe.rpki.ta.BadOptions;
import org.joda.time.Period;

import javax.security.auth.x500.X500Principal;
import java.io.File;
import java.net.URI;

public class Env {

    public static Config config(ProgramOptions options) throws BadOptions {
        final Config config = byEnvironment(options.getEnv());

        if (options.hasPersistentStoragePath()) {
            final File storageDirectory = new File(options.getPersistentStoragePath());
            if (!storageDirectory.isDirectory()) {
                throw new BadOptions(String.format("Persistant storage directory '%s' does not exist.", storageDirectory.getAbsolutePath()));
            }

            config.setPersistentStorageDir(storageDirectory.getAbsolutePath());
        }

        return config;
    }

    private static Config byEnvironment(String envName) throws BadOptions {
        if ("test".equals(envName)) {
            return EnvStub.test();
        }
        if (envName == null || "local".equals(envName)) {
            return local();
        }
        if ("dev".equals(envName)) {
            return dev();
        }
        if ("prepdev".equals(envName)) {
            return prepdev();
        }
        if ("pilot".equals(envName)) {
            return pilot();
        }
        if ("production".equals(envName)) {
            return production();
        }

        throw new BadOptions("Unknown environment name: " + envName);
    }

    public static Config production() {
        final Config config = nCipherConf();
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
        final Config config = EnvStub.testConfig();
        config.setTaCertificatePublicationUri(URI.create("rsync://rpki.dev.ripe.net/ta/"));
        config.setTaProductsPublicationUri(URI.create("rsync://rpki.dev.ripe.net/repository/"));
        return config;
    }

    public static Config prepdev() {
        final Config config = EnvStub.testConfig();
        config.setPersistentStorageDir("/export/bad/ta-ca/data/");
        config.setTaCertificatePublicationUri(URI.create("rsync://rpki.prepdev.ripe.net/ta/"));
        config.setTaProductsPublicationUri(URI.create("rsync://rpki.prepdev.ripe.net/repository/"));
        config.setNotificationUri(URI.create("https://pub-server.elasticbeanstalk.com/notification.xml"));
        return config;
    }

    public static Config pilot() {
        final Config config = EnvStub.testConfig();
        config.setPersistentStorageDir("/export/bad/ta-ca/data/");
        config.setTaCertificatePublicationUri(URI.create("rsync://localcert.ripe.net/ta/"));
        config.setTaProductsPublicationUri(URI.create("rsync://localcert.ripe.net/repository/"));
        config.setTrustAnchorName(new X500Principal("CN=ripe-ncc-pilot"));
        config.setNotificationUri(URI.create("https://localcert.ripe.net/rrdp/notification.xml"));
        return config;
    }

    public static Config local() {
        final Config config = EnvStub.testConfig();
        config.setTaCertificatePublicationUri(URI.create("rsync://localhost:10873/ta/"));
        config.setTaProductsPublicationUri(URI.create("rsync://localhost:10873/repository/"));
        return config;
    }

    private static Config nCipherConf() {
        final Config config = new Config();
        config.setSignatureProvider("nCipherKM");
        config.setKeystoreProvider("nCipherKM");
        config.setKeypairGeneratorProvider("nCipherKM");
        config.setKeystoreType("ncipher.sworld");
        return config;
    }

    static Config sunRsaConf() {
        final Config config = new Config();
        config.setSignatureProvider("SunRsaSign");
        config.setKeystoreProvider("SUN");
        config.setKeypairGeneratorProvider("SunRsaSign");
        config.setKeystoreType("JKS");
        return config;
    }
}
