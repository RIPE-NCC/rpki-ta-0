package net.ripe.rpki.ta.persistence;

import net.ripe.rpki.ta.TA;
import net.ripe.rpki.ta.config.Config;
import net.ripe.rpki.ta.config.Env;
import net.ripe.rpki.ta.serializers.TAState;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.io.IOException;

import static org.junit.Assert.*;

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

public class TAPersistenceTest {

    private static final String STORAGE_DIR = "src/test/resources/tmp";

    @Before
    public void setUp() throws Exception {
        cleanTaXml();
    }

    @After
    public void tearDown() throws Exception {
        cleanTaXml();
    }

    @Test
    public void saveAndLoad() throws Exception {
        final Config testConfig = Env.development();
        testConfig.setPersistentStorageDir(STORAGE_DIR);

        final TA ta = new TA(testConfig);
        final TAState taState = ta.initialiseTaState();
        ta.persist(taState);

        assertEquals(taState, ta.loadTAState());
    }

    @Test(expected = IOException.class)
    public void cantSaveTwice() throws Exception {
        final Config testConfig = Env.development();
        testConfig.setPersistentStorageDir(STORAGE_DIR);

        final TA ta = new TA(testConfig);
        TAState taState = ta.initialiseTaState();
        ta.persist(taState);
        ta.persist(taState);
    }

    private void cleanTaXml() {
        new File(STORAGE_DIR + "/ta.xml").delete();
    }

}