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
        assertInvalidCombinationsOfOptions("--initialise --initialise-from-old=./test --env=development", "Cannot have both --initialise and --initialise-from-old options.");

        assertInvalidCombinationsOfOptions("--generate-ta-certificate --initialise --env=development", "Cannot have both --generate-ta-certificate and --initialise options.");
        assertInvalidCombinationsOfOptions("--generate-ta-certificate --initialise-from-old=./test --env=development", "Cannot have both --generate-ta-certificate and --initialise-from-old options.");
        assertInvalidCombinationsOfOptions("--generate-ta-certificate --print-tal --env=development", "Cannot have both --generate-ta-certificate and --print-tal options.");
        assertInvalidCombinationsOfOptions("--generate-ta-certificate --export-ta-certificate=./ --env=development", "Cannot have both --generate-ta-certificate and --export-ta-certificate options.");

        assertInvalidCombinationsOfOptions("--export-ta-certificate=./ --initialise --env=development", "Cannot have both --export-ta-certificate and --initialise options.");
        assertInvalidCombinationsOfOptions("--export-ta-certificate=./ --initialise-from-old=./test --env=development", "Cannot have both --export-ta-certificate and --initialise-from-old options.");
        assertInvalidCombinationsOfOptions("--export-ta-certificate=./ --print-tal --env=development", "Cannot have both --export-ta-certificate and --print-tal options.");

        assertInvalidCombinationsOfOptions("--print-tal --initialise --env=development", "Cannot have both --print-tal and --initialise options.");
        assertInvalidCombinationsOfOptions("--print-tal --initialise-from-old=./test --env=development", "Cannot have both --print-tal and --initialise-from-old options.");

        assertInvalidCombinationsOfOptions("--process=./test --print-tal --env=development", "Cannot have both --process and --print-tal options.");
        assertInvalidCombinationsOfOptions("--process=./test --export-ta-certificate=./ --env=development", "Cannot have both --process and --export-ta-certificate options.");
        assertInvalidCombinationsOfOptions("--process=./test --generate-ta-certificate --env=development", "Cannot have both --process and --generate-ta-certificate options.");
        assertInvalidCombinationsOfOptions("--process=./test --initialise-from-old=./test --env=development", "Cannot have both --process and --initialise-from-old options.");
        assertInvalidCombinationsOfOptions("--process=./test --initialise --env=development", "Cannot have both --process and --initialise options.");

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

