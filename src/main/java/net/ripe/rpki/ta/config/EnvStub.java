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


import org.joda.time.Period;

import javax.security.auth.x500.X500Principal;
import java.net.URI;
import java.nio.file.Paths;

public class EnvStub {
    public static final Config _testConfig = testConfig();

    static Config testConfig() {
        final String HOME = System.getProperty("user.home");
        Config config = new Config();
        config.setPersistentStorageDir(Paths.get(HOME, "export/bad/certification/ta/data").toAbsolutePath().toString());
        config.setMinimumValidityPeriod(Period.months(1));
        config.setUpdatePeriod(Period.months(3));
        config.setTrustAnchorName(new X500Principal("CN=RIPE-NCC-TA-TEST"));
        config.setNotificationUri(URI.create("https://localhost:7788/notification.xml"));
        return config;
    }

    public static Config getTestConfig() {
        return _testConfig;
    }

    public static Config test() {
        final Config config = Env.withSunRsaConf(getTestConfig());
        config.setTaCertificatePublicationUri(URI.create("rsync://localhost:10873/ta/"));
        config.setTaProductsPublicationUri(URI.create("rsync://localhost:10873/repository/"));
        return config;
    }
}
