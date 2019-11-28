package net.ripe.rpki.ta.config;


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
        assertInvalidCombinationsOfOptions("--initialise --initialise-from-old=./test --env=dev", "Cannot have both --initialise and --initialise-from-old options.");

        assertInvalidCombinationsOfOptions("--generate-ta-certificate --initialise --env=dev", "Cannot have both --generate-ta-certificate and --initialise options.");
        assertInvalidCombinationsOfOptions("--generate-ta-certificate --initialise-from-old=./test --env=dev", "Cannot have both --generate-ta-certificate and --initialise-from-old options.");
        assertInvalidCombinationsOfOptions("--generate-ta-certificate --print-tal=./test.tal --env=dev", "Cannot have both --generate-ta-certificate and --print-tal options.");
        assertInvalidCombinationsOfOptions("--generate-ta-certificate --export-ta-certificate=./ --env=dev", "Cannot have both --generate-ta-certificate and --export-ta-certificate options.");

        assertInvalidCombinationsOfOptions("--export-ta-certificate=./ --initialise --env=dev", "Cannot have both --export-ta-certificate and --initialise options.");
        assertInvalidCombinationsOfOptions("--export-ta-certificate=./ --initialise-from-old=./test --env=dev", "Cannot have both --export-ta-certificate and --initialise-from-old options.");
        assertInvalidCombinationsOfOptions("--export-ta-certificate=./ --print-tal=./test.tal --env=dev", "Cannot have both --export-ta-certificate and --print-tal options.");

        assertInvalidCombinationsOfOptions("--print-tal=./test.tal --initialise --env=dev", "Cannot have both --print-tal and --initialise options.");
        assertInvalidCombinationsOfOptions("--print-tal=./test.tal --initialise-from-old=./test --env=dev", "Cannot have both --print-tal and --initialise-from-old options.");

        assertInvalidCombinationsOfOptions("--request=./test.in --response=./test.out --print-tal=./test.tal --env=dev", "Cannot have both --request and --print-tal options.");
        assertInvalidCombinationsOfOptions("--request=./test.in --response=./test.out --export-ta-certificate=./ --env=dev", "Cannot have both --request and --export-ta-certificate options.");
        assertInvalidCombinationsOfOptions("--request=./test.in --response=./test.out --generate-ta-certificate --env=dev", "Cannot have both --request and --generate-ta-certificate options.");
        assertInvalidCombinationsOfOptions("--request=./test.in --response=./test.out --initialise-from-old=./test --env=dev", "Cannot have both --request and --initialise-from-old options.");
        assertInvalidCombinationsOfOptions("--request=./test.in --response=./test.out --initialise --env=dev", "Cannot have both --request and --initialise options.");

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

