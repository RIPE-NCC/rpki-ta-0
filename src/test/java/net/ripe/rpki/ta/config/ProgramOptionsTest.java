package net.ripe.rpki.ta.config;


import net.ripe.rpki.ta.exception.BadOptionsException;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class ProgramOptionsTest {
    @Test
    public void testEnvOptNotProvided() {
        assertInvalidCombinationsOfOptions("", "Doesn't have meaningful options.");
    }

    @Test
    public void testIncompatibleOptions() {
        assertInvalidCombinationsOfOptions("--generate-ta-certificate --initialise --env=dev", "Cannot have both --generate-ta-certificate and --initialise options.");
        assertInvalidCombinationsOfOptions("--generate-ta-certificate --print-tal=./test.tal --env=dev", "Cannot have both --generate-ta-certificate and --print-tal options.");
        assertInvalidCombinationsOfOptions("--generate-ta-certificate --export-ta-certificate=./ --env=dev", "Cannot have both --generate-ta-certificate and --export-ta-certificate options.");

        assertInvalidCombinationsOfOptions("--export-ta-certificate=./ --initialise --env=dev", "Cannot have both --export-ta-certificate and --initialise options.");
        assertInvalidCombinationsOfOptions("--export-ta-certificate=./ --print-tal=./test.tal --env=dev", "Cannot have both --export-ta-certificate and --print-tal options.");

        assertInvalidCombinationsOfOptions("--print-tal=./test.tal --initialise --env=dev", "Cannot have both --print-tal and --initialise options.");

        assertInvalidCombinationsOfOptions("--request=./test.in --response=./test.out --print-tal=./test.tal --env=dev", "Cannot have both --request and --print-tal options.");
        assertInvalidCombinationsOfOptions("--request=./test.in --response=./test.out --export-ta-certificate=./ --env=dev", "Cannot have both --request and --export-ta-certificate options.");
        assertInvalidCombinationsOfOptions("--request=./test.in --response=./test.out --generate-ta-certificate --env=dev", "Cannot have both --request and --generate-ta-certificate options.");
        assertInvalidCombinationsOfOptions("--request=./test.in --response=./test.out --initialise --env=dev", "Cannot have both --request and --initialise options.");

    }

    @Test
    public void testDependencyMissingOptions() {
        assertInvalidCombinationsOfOptions("--request=./test.in", "Doesn't have meaningful options.");
        assertInvalidCombinationsOfOptions("--response=./test.out", "Doesn't have meaningful options.");

        assertInvalidCombinationsOfOptions("--env=dev --print-tal=./test.tal --force-new-ta-certificate", "Option --force-new-ta-certificate doesn't make sense without --request option.");
        assertInvalidCombinationsOfOptions("--env=dev --print-tal=./test.tal --revoke-non-requested-objects", "Option --revoke-non-requested-objects doesn't make sense without --request option.");
    }

    private void assertInvalidCombinationsOfOptions(final String args, final String message) {
        assertThatThrownBy(() -> new ProgramOptions(args.split(" ")).validateOptions())
                .isInstanceOf(BadOptionsException.class)
                .hasMessage(message);
    }
}