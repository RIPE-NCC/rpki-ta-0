package net.ripe.rpki.ta.integration;

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

import com.google.common.io.Files;
import net.ripe.rpki.ta.Main;
import net.ripe.rpki.ta.TA;
import net.ripe.rpki.ta.config.Env;
import net.ripe.rpki.ta.domain.TAState;
import org.junit.Before;
import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.PrintStream;
import java.math.BigInteger;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.*;

public class MainIntegrationTest extends AbstractIntegrationTest {

    private static final String TA_XML_PATH = "/export/bad/certification/ta/data/ta.xml";
    private static final String TAL_PATH = "/export/bad/certification/ta/data/test.tal";

    @Before
    public void setup() {
        deleteFile(TA_XML_PATH);
        deleteFile(TAL_PATH);
    }

    @Before
    public void teardown() {
        deleteFile(TA_XML_PATH);
        deleteFile(TAL_PATH);
    }

    @Test
    public void initialize_development() {
        assertThat(run("--initialise --env=development").exitCode, is(0));

        assertThat(readFile(TA_XML_PATH), containsString("<TA>"));
    }

    @Test
    public void print_ta() {
        run("--initialise-from-old=./src/test/resources/ta-legacy.xml --env=development");

        run("--print-tal="+TAL_PATH +" --env=development");

        assertThat(readFile(TAL_PATH), equalTo(
                "rsync://localhost:10873/ta/RIPE-NCC-TA-TEST.cer\n"+
                        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApIXenLOBfyo7cOnm4mGKmYxsoWCp28dw3XJAoZNWPDK8i9MxYACpwfz7bj" +
                        "yGma1BWPBJuievNd6nriFI+3WG+wt2bnO2ZmiLenCwMtm8bu7BeldpWRwlAnRp4t4IL6sZ7T9bF+4sTrv1qiEANqam0mhtLtUfbWXV" +
                        "5Z4mjgnNur7fJH2lIOm7Oc2/tok1rid8WsPe18zuvgwA3M0fKQ/Oa4SMXKnHr3fg2cHAm1cfEEvhMKa3rUAvsKGVEYeTJNg6rh3IRn" +
                        "jWhZ8GmE1ywl/9qMa2z4YsUi9Bx9U+/zMS8qpJn/q6XBbZ8XYTTFvSWfXd6b82jSfABa4ukIDCUF/QFwIDAQAB")
        );
    }
    
    @Test
    public void generate_ta_certificate() throws Exception {
        final Main.Exit exit = run("--initialise-from-old=./src/test/resources/ta-legacy.xml --env=development");
        assertEquals(0, exit.exitCode);

        final TAState taState = new TA(Env.development()).loadTAState();
        assertEquals(BigInteger.valueOf(29L), taState.getLastIssuedCertificateSerial());
    }

    @Test
    public void priocess_request() throws Exception {
        assertEquals(0, run("--initialise --env=development").exitCode);

        final File tmpResponses = Files.createTempDir();
        tmpResponses.deleteOnExit();
        final File response = new File(tmpResponses.getAbsolutePath(), "response.xml");
        
        assertEquals(0, run("--request=./src/test/resources/ta-request.xml --response=" + response.getAbsolutePath() + " --env=development").exitCode);
        final TAState taState1 = new TA(Env.development()).loadTAState();
        assertEquals(BigInteger.valueOf(3L), taState1.getLastIssuedCertificateSerial());
        assertEquals(BigInteger.valueOf(1L), taState1.getLastMftSerial());
        assertEquals(BigInteger.valueOf(1L), taState1.getLastCrlSerial());
        assertEquals(1, taState1.getSignedProductionCertificates().size());
        assertEquals(1, taState1.getSignedManifests().size());
        assertNull(taState1.getCrl().getCrl().getRevokedCertificates());

        assertEquals(0, run("--request=./src/test/resources/ta-request.xml --response=" + response.getAbsolutePath() + " --env=development").exitCode);
        final TAState taState2 = new TA(Env.development()).loadTAState();
        assertEquals(BigInteger.valueOf(5L), taState2.getLastIssuedCertificateSerial());
        assertEquals(BigInteger.valueOf(2L), taState2.getLastMftSerial());
        assertEquals(BigInteger.valueOf(2L), taState2.getLastCrlSerial());
        assertEquals(2, taState2.getSignedProductionCertificates().size());
        assertEquals(2, taState2.getSignedManifests().size());
        assertEquals(1, taState2.getCrl().getCrl().getRevokedCertificates().size());

        assertEquals(0, run("--request=./src/test/resources/ta-request.xml --response=" + response.getAbsolutePath() + " --env=development").exitCode);
        final TAState taState3 = new TA(Env.development()).loadTAState();
        assertEquals(BigInteger.valueOf(7L), taState3.getLastIssuedCertificateSerial());
        assertEquals(BigInteger.valueOf(3L), taState3.getLastMftSerial());
        assertEquals(BigInteger.valueOf(3L), taState3.getLastCrlSerial());
        assertEquals(3, taState3.getSignedProductionCertificates().size());
        assertEquals(3, taState3.getSignedManifests().size());
        assertEquals(2, taState3.getCrl().getCrl().getRevokedCertificates().size());


    }


}
