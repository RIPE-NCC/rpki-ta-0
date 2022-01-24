package net.ripe.rpki.ta.persistence;

import net.ripe.rpki.ta.TA;
import net.ripe.rpki.ta.config.Config;
import net.ripe.rpki.ta.config.Env;
import net.ripe.rpki.ta.domain.TAState;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.math.BigInteger;

import static org.junit.Assert.assertEquals;


public class TAPersistenceTest {

    @Rule
    public TemporaryFolder tempFolder = new TemporaryFolder();

    @Test
    public void saveAndLoad() throws Exception {
        final Config testConfig = Env.dev();
        testConfig.setPersistentStorageDir(tempFolder.getRoot().getAbsolutePath());

        final TA ta = new TA(testConfig);
        final TAState taState = ta.initialiseTaState();
        ta.persist(taState);

        assertEquals(taState, ta.loadTAState());

        // TA serial should be set to 1 upon initialisation:
        assertEquals(BigInteger.ONE, taState.getLastIssuedCertificateSerial());
    }

}