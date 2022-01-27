package net.ripe.rpki.ta.persistence;

import net.ripe.rpki.ta.TA;
import net.ripe.rpki.ta.config.Config;
import net.ripe.rpki.ta.config.Env;
import net.ripe.rpki.ta.domain.TAState;
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

        final TA ta = new TA(testConfig);
        final TAState taState = ta.initialiseTaState();
        ta.persist(taState);

        assertThat(taState).isEqualTo(ta.loadTAState());

        // TA serial should be set to 1 upon initialisation:
        assertThat(taState.getLastIssuedCertificateSerial()).isOne();
    }

}