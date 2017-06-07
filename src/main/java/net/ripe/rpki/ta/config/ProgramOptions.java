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


import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.OptionBuilder;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

import java.io.PrintWriter;
import java.io.StringWriter;

public class ProgramOptions {

    private static final String ENV_OPT = "env";
    private static final String INITIALISE_OPT = "initialise";
    private static final String INITIALISE_FROM_OLD_OPT = "initialise-from-old";
    private static final String GENERATE_TA_CERTIFICATE_OPT = "generate-ta-certificate";
    private static final String PRINT_TA_CERTIFICATE_OPT = "print-ta-certificate";
    private static final String PRINT_TAL_OPT = "print-tal";

    private final CommandLine commandLine;
    private final Options options;

    public ProgramOptions(String[] args) throws ParseException {
        options = new Options();
        options.addOption(Option.builder().longOpt(ENV_OPT).
                hasArg().
                desc("Must be one of 'production' or 'development'").
                build());

        options.addOption(Option.builder().longOpt(INITIALISE_FROM_OLD_OPT).
                hasArg().
                desc("Path to the file with old-style trust anchor serialized state").
                build());

        options.addOption(Option.builder().longOpt(INITIALISE_OPT).
                hasArg(false).
                desc("Initialise the trust anchor key pair and persist its state").
                build());

        options.addOption(Option.builder().longOpt(GENERATE_TA_CERTIFICATE_OPT).
                hasArg(false).
                desc("Generate trust anchor certificate and persist its state").
                build());

        options.addOption(Option.builder().longOpt(PRINT_TA_CERTIFICATE_OPT).
                hasArg(false).
                desc("Print trust anchor certificate").
                build());

        options.addOption(Option.builder().longOpt(PRINT_TAL_OPT).
                hasArg(false).
                desc("Print TAL").
                build());

        commandLine = new DefaultParser().parse(options, args);
    }

    public boolean hasInitialise() {
        return commandLine.hasOption(INITIALISE_OPT);
    }

    public boolean hasAnyMeaningfulOption() {
        return hasInitialise() || hasInitialiseFromOld() || hasGenerateTACertificate();
    }

    public String getUsageString() {
        final HelpFormatter hf = new HelpFormatter();
        final StringWriter sw = new StringWriter();
        final PrintWriter pw = new PrintWriter(sw);
        hf.printHelp(pw, hf.getWidth(), "ta.sh", null, options, hf.getLeftPadding(), hf.getDescPadding(), "", false);
        return sw.toString();
    }

    public boolean hasEnv() {
        return commandLine.hasOption(ENV_OPT);
    }

    public String getEnv() {
        return commandLine.getOptionValue(ENV_OPT);
    }

    public boolean hasInitialiseFromOld() {
        return commandLine.hasOption(INITIALISE_FROM_OLD_OPT);
    }

    public boolean hasGenerateTACertificate() {
        return commandLine.hasOption(GENERATE_TA_CERTIFICATE_OPT);
    }

    public String getOldTaFilePath() {
        return commandLine.getOptionValue(INITIALISE_FROM_OLD_OPT);
    }

    @Override
    public String toString() {
        return "ProgramOptions{" +
                "commandLine=" + commandLine +
                '}';
    }
}
