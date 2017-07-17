package net.ripe.rpki.ta.config;

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

import net.ripe.rpki.ta.BadOptions;
import org.junit.Test;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.*;

public class ProgramOptionsTest {

    @Test
    public void testEnvOptNotProvided() {
        assertInvalidCombinationsOfOptions("", "Doesn't have meaningful options.");
    }

    @Test
    public void testIncompatibleOptions() {
        assertInvalidCombinationsOfOptions("--initialise --initialise-from-old=./test --env=development", "Cannot have both --initialise and --initialise-from-old options.");

        assertInvalidCombinationsOfOptions("--generate-ta-certificate --initialise --env=development", "Cannot have both --generate-ta-certificate and --initialise options.");
        assertInvalidCombinationsOfOptions("--generate-ta-certificate --initialise-from-old=./test --env=development", "Cannot have both --generate-ta-certificate and --initialise-from-old options.");
        assertInvalidCombinationsOfOptions("--generate-ta-certificate --print-tal=./test.tal --env=development", "Cannot have both --generate-ta-certificate and --print-tal options.");
        assertInvalidCombinationsOfOptions("--generate-ta-certificate --export-ta-certificate=./ --env=development", "Cannot have both --generate-ta-certificate and --export-ta-certificate options.");

        assertInvalidCombinationsOfOptions("--export-ta-certificate=./ --initialise --env=development", "Cannot have both --export-ta-certificate and --initialise options.");
        assertInvalidCombinationsOfOptions("--export-ta-certificate=./ --initialise-from-old=./test --env=development", "Cannot have both --export-ta-certificate and --initialise-from-old options.");
        assertInvalidCombinationsOfOptions("--export-ta-certificate=./ --print-tal=./test.tal --env=development", "Cannot have both --export-ta-certificate and --print-tal options.");

        assertInvalidCombinationsOfOptions("--print-tal=./test.tal --initialise --env=development", "Cannot have both --print-tal and --initialise options.");
        assertInvalidCombinationsOfOptions("--print-tal=./test.tal --initialise-from-old=./test --env=development", "Cannot have both --print-tal and --initialise-from-old options.");

        assertInvalidCombinationsOfOptions("--request=./test.in --response=./test.out --print-tal=./test.tal --env=development", "Cannot have both --request and --print-tal options.");
        assertInvalidCombinationsOfOptions("--request=./test.in --response=./test.out --export-ta-certificate=./ --env=development", "Cannot have both --request and --export-ta-certificate options.");
        assertInvalidCombinationsOfOptions("--request=./test.in --response=./test.out --generate-ta-certificate --env=development", "Cannot have both --request and --generate-ta-certificate options.");
        assertInvalidCombinationsOfOptions("--request=./test.in --response=./test.out --initialise-from-old=./test --env=development", "Cannot have both --request and --initialise-from-old options.");
        assertInvalidCombinationsOfOptions("--request=./test.in --response=./test.out --initialise --env=development", "Cannot have both --request and --initialise options.");

    }

    @Test
    public void testDependencyMissingOptions() {
        assertInvalidCombinationsOfOptions("--request=./test.in", "Doesn't have meaningful options.");
        assertInvalidCombinationsOfOptions("--response=./test.out", "Doesn't have meaningful options.");
    }

    private void assertInvalidCombinationsOfOptions(final String args, final String message) {
        try {
            new ProgramOptions(args.split(" ")).validateOptions();
            fail("should not accept "+args);
        } catch (final BadOptions badOptions) {
            assertThat(badOptions.getMessage(), is(message));
        }
    }

}

