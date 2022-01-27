package net.ripe.rpki.ta.config;



import net.ripe.rpki.ta.exception.BadOptionsException;
import org.joda.time.Period;

import javax.security.auth.x500.X500Principal;
import java.io.File;
import java.net.URI;

public class Env {

    public static Config config(ProgramOptions options) throws BadOptionsException {
        final Config config = byEnvironment(options.getEnv());

        if (options.hasPersistentStoragePath()) {
            final File storageDirectory = new File(options.getPersistentStoragePath());
            if (!storageDirectory.isDirectory()) {
                throw new BadOptionsException(String.format("Persistant storage directory '%s' does not exist.", storageDirectory.getAbsolutePath()));
            }

            config.setPersistentStorageDir(storageDirectory.getAbsolutePath());
        }

        return config;
    }

    private static Config byEnvironment(String envName) throws BadOptionsException {
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

        throw new BadOptionsException("Unknown environment name: " + envName);
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
        final Config config = withSunRsaConf(EnvStub.testConfig());
        config.setTaCertificatePublicationUri(URI.create("rsync://rpki.dev.ripe.net/ta/"));
        config.setTaProductsPublicationUri(URI.create("rsync://rpki.dev.ripe.net/repository/"));
        return config;
    }

    public static Config prepdev() {
        final Config config = withNCipherConf(EnvStub.testConfig());
        config.setPersistentStorageDir("/export/bad/ta-ca/data/");
        config.setTaCertificatePublicationUri(URI.create("rsync://rpki.prepdev.ripe.net/ta/"));
        config.setTaProductsPublicationUri(URI.create("rsync://rpki.prepdev.ripe.net/repository/"));
        config.setNotificationUri(URI.create("https://rrdp.prepdev.ripe.net/notification.xml"));
        return config;
    }

    public static Config pilot() {
        final Config config = withSunRsaConf(EnvStub.testConfig());
        config.setPersistentStorageDir("/export/bad/ta-ca/data/");
        config.setTaCertificatePublicationUri(URI.create("rsync://localcert.ripe.net/ta/"));
        config.setTaProductsPublicationUri(URI.create("rsync://localcert.ripe.net/repository/"));
        config.setTrustAnchorName(new X500Principal("CN=ripe-ncc-pilot"));
        config.setNotificationUri(URI.create("https://localcert.ripe.net/rrdp/notification.xml"));
        return config;
    }

    public static Config local() {
        final Config config = withSunRsaConf(EnvStub.testConfig());
        config.setTaCertificatePublicationUri(URI.create("rsync://localhost:10873/ta/"));
        config.setTaProductsPublicationUri(URI.create("rsync://localhost:10873/repository/"));
        return config;
    }

    private static Config nCipherConf() {
        return withNCipherConf(new Config());
    }

    private static Config withNCipherConf(final Config config) {
        config.setSignatureProvider("nCipherKM");
        config.setKeystoreProvider("nCipherKM");
        config.setKeypairGeneratorProvider("nCipherKM");
        config.setKeystoreType("ncipher.sworld");
        return config;
    }

    static Config withSunRsaConf(Config config) {
        config.setSignatureProvider("SunRsaSign");
        config.setKeystoreProvider("SUN");
        config.setKeypairGeneratorProvider("SunRsaSign");
        config.setKeystoreType("JKS");
        return config;
    }
}
