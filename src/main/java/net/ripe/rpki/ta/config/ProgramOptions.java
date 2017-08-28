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
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

import java.io.PrintWriter;
import java.io.StringWriter;

public class ProgramOptions {

    private static final String ENV_OPT = "env";
    private static final String INITIALISE_OPT = "initialise";
    private static final String INITIALISE_FROM_OLD_OPT = "initialise-from-old";
    private static final String GENERATE_TA_CERTIFICATE_OPT = "generate-ta-certificate";
    private static final String EXPORT_TA_CERTIFICATE_OPT = "export-ta-certificate";
    private static final String PRINT_TAL_OPT = "print-tal";
    private static final String REQUEST_OPT = "request";
    private static final String RESPONSE_OPT = "response";

    private final CommandLine commandLine;
    private final static Options options;

    static {
        options = new Options();
        options.addOption(Option.builder().longOpt(ENV_OPT).
                hasArg().
                desc("Must be one of 'local', 'dev', 'prepdev' or 'production'").
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

        options.addOption(Option.builder().longOpt(EXPORT_TA_CERTIFICATE_OPT).
                hasArg().
                desc("Print trust anchor certificate to the file set as the option value").
                build());

        options.addOption(Option.builder().longOpt(PRINT_TAL_OPT).
                hasArg().
                desc("Print TAL to file").
                build());

        options.addOption(Option.builder().longOpt(REQUEST_OPT).
                hasArg().
                desc("Path to the request file to be processed").
                build());

        options.addOption(Option.builder().longOpt(RESPONSE_OPT).
                hasArg().
                desc("Path to the response file that was processed").
                build());
    }

    public ProgramOptions(String... args) throws BadOptions {
        try {
            commandLine = new DefaultParser().parse(options, args);
        } catch (ParseException e) {
            throw new BadOptions(e);
        }
    }

    public void validateOptions() throws BadOptions {
        if (!hasEnv() || !(hasInitialiseFromOldOption() || hasInitialiseOption() ||
                hasGenerateTACertificateOption() || hasExportCertificateOption() || hasPrintTALOption() || hasRequestOption() || hasResponseOption())) {
            throw new BadOptions("Doesn't have meaningful options.");
        }

        checkIncompatible(INITIALISE_OPT, INITIALISE_FROM_OLD_OPT);

        checkIncompatible(GENERATE_TA_CERTIFICATE_OPT, INITIALISE_OPT, INITIALISE_FROM_OLD_OPT, PRINT_TAL_OPT, EXPORT_TA_CERTIFICATE_OPT);

        checkIncompatible(EXPORT_TA_CERTIFICATE_OPT, INITIALISE_OPT, INITIALISE_FROM_OLD_OPT);

        checkIncompatible(PRINT_TAL_OPT, INITIALISE_OPT, INITIALISE_FROM_OLD_OPT);

        checkIncompatible(REQUEST_OPT, INITIALISE_OPT, INITIALISE_FROM_OLD_OPT, GENERATE_TA_CERTIFICATE_OPT, EXPORT_TA_CERTIFICATE_OPT, PRINT_TAL_OPT);

        checkIncompatible(EXPORT_TA_CERTIFICATE_OPT, PRINT_TAL_OPT);

        checkDependency(REQUEST_OPT, RESPONSE_OPT);

        checkDependency(RESPONSE_OPT, REQUEST_OPT);
    }

    private void checkDependency(final String option, final String... dependencies) throws BadOptions {
        for (final String dependency : dependencies) {
            if (commandLine.hasOption(option) && !commandLine.hasOption(dependency)) {
                throw new BadOptions("Doesn't have meaningful options.");
            }
        }
    }

    private void checkIncompatible(final String option, final String... incompatibleList) throws BadOptions {
        for (final String incompatibleOption : incompatibleList) {
            if (commandLine.hasOption(option) && commandLine.hasOption(incompatibleOption)) {
                throw new BadOptions("Cannot have both --" + option + " and --" + incompatibleOption + " options.");
            }
        }
    }

    public boolean hasInitialiseOption() {
        return commandLine.hasOption(INITIALISE_OPT);
    }

    public boolean hasExportCertificateOption() {
        return commandLine.hasOption(EXPORT_TA_CERTIFICATE_OPT);
    }

    public String getPrintCertificateFileName() {
        return commandLine.getOptionValue(EXPORT_TA_CERTIFICATE_OPT);
    }

    public boolean hasPrintTALOption() {
        return commandLine.hasOption(PRINT_TAL_OPT);
    }

    public boolean hasRequestOption() {
        return commandLine.hasOption(REQUEST_OPT);
    }

    public boolean hasResponseOption() {
        return commandLine.hasOption(RESPONSE_OPT);
    }

    public boolean hasEnv() {
        return commandLine.hasOption(ENV_OPT);
    }

    public String getEnv() {
        return commandLine.getOptionValue(ENV_OPT);
    }

    public boolean hasInitialiseFromOldOption() {
        return commandLine.hasOption(INITIALISE_FROM_OLD_OPT);
    }

    public boolean hasGenerateTACertificateOption() {
        return commandLine.hasOption(GENERATE_TA_CERTIFICATE_OPT);
    }

    public String getOldTaFilePath() {
        return commandLine.getOptionValue(INITIALISE_FROM_OLD_OPT);
    }

    public String getTalFilePath() {
        return commandLine.getOptionValue(PRINT_TAL_OPT);
    }

    public String getRequestFile() {
        return commandLine.getOptionValue(REQUEST_OPT);
    }

    public String getResponseFile() {
        return commandLine.getOptionValue(RESPONSE_OPT);
    }

    public static String getUsageString() {
        final HelpFormatter hf = new HelpFormatter();
        final StringWriter sw = new StringWriter();
        final PrintWriter pw = new PrintWriter(sw);
        hf.printHelp(pw, hf.getWidth(), "ta.sh", null, options, hf.getLeftPadding(), hf.getDescPadding(), "", false);
        return sw.toString();
    }

    @Override
    public String toString() {
        return "ProgramOptions{" +
                "commandLine=" + commandLine +
                '}';
    }
}
