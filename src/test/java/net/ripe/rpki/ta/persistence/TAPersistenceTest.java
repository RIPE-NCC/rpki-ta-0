package net.ripe.rpki.ta.persistence;

import net.ripe.rpki.ta.TA;
import net.ripe.rpki.ta.config.Config;
import net.ripe.rpki.ta.config.Env;
import net.ripe.rpki.ta.domain.TAState;
import net.ripe.rpki.ta.domain.TAStateBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.math.BigInteger;

import static org.assertj.core.api.Assertions.assertThat;

public class TAPersistenceTest {

    @Test
    public void testSaveAndLoad(@TempDir File tempFolder) throws Exception {
        final Config testConfig = Env.dev();
        testConfig.setPersistentStorageDir(tempFolder.getAbsolutePath());

        final TA ta = TA.initialise(testConfig);
        ta.persist();

        assertThat(ta.getState()).isEqualTo(TA.load(testConfig).getState());

        // TA serial should be set to 1 upon initialisation:
        assertThat(ta.getState().getLastIssuedCertificateSerial()).isOne();
    }

}
