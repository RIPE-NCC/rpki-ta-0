package net.ripe.rpki.ta.config;



import net.ripe.rpki.ta.BadOptions;
import org.joda.time.Period;

import javax.security.auth.x500.X500Principal;
import java.net.URI;

public class Env {

    public static Config config(String envName) throws BadOptions {
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
        config.setNotificationUri(URI.create("http://pub-server.elasticbeanstalk.com/notification.xml"));
        return config;
    }

    public static Config pilot() {
        final Config config = EnvStub.testConfig();
        config.setPersistentStorageDir("/export/bad/ta-ca/data/");
        config.setTaCertificatePublicationUri(URI.create("rsync://localcert.ripe.net/ta/"));
        config.setTaProductsPublicationUri(URI.create("rsync://localcert.ripe.net/repository/"));
        config.setTrustAnchorName(new X500Principal("CN=ripe-ncc-pilot"));
        config.setNotificationUri(URI.create("http://localcert.ripe.net:7788/notification.xml"));
        return config;
    }

    public static Config local() {
        final Config config = EnvStub.testConfig();
        config.setTaCertificatePublicationUri(URI.create("rsync://localhost:10873/ta/"));
        config.setTaProductsPublicationUri(URI.create("rsync://localhost:10873/online/"));
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
