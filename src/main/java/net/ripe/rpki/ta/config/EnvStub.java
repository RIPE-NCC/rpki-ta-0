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
