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

import org.junit.Before;
import org.junit.Test;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

public class MainIntegrationTest extends AbstractIntegrationTest {

    private static final String TA_XML_PATH = "/export/bad/certification/ta/data/ta.xml";

    @Before
    public void setup() {
        deleteFile(TA_XML_PATH);
    }

    @Before public void teardown() {
        deleteFile(TA_XML_PATH);
    }

    @Test
    public void initialize_development() {
        final int exit = run("--initialise --env=development");
        assertThat(exit, is(0));

        assertThat(readFile(TA_XML_PATH), containsString("<TA>"));
    }

    @Test
    public void check_options() {
        assertThat(run("--initialise --env=development --initialise-from-old=xxx"), is(2));
        assertThat(run("--initialise --env=development --generate-ta-certificate=output.xml"), is(2));
        assertThat(run("--initialise --env=development --print-ta-certificate=output.xml"), is(2));
        assertThat(run("--print-tal --env=development --print-ta-certificate=output.xml"), is(2));
        assertThat(run("--generate-ta-certificate --env=development --print-ta-certificate=output.xml"), is(2));
    }

}
