package net.ripe.rpki.ta.config;



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
    private static final String GENERATE_TA_CERTIFICATE_OPT = "generate-ta-certificate";
    private static final String EXPORT_TA_CERTIFICATE_OPT = "export-ta-certificate";
    private static final String PRINT_TAL_OPT = "print-tal";
    private static final String REQUEST_OPT = "request";
    private static final String RESPONSE_OPT = "response";
    private static final String STORAGE_DIRECTORY = "storage-directory";
    public static final String FORCE_NEW_TA_CERT_OPT = "force-new-ta-certificate";

    private final CommandLine commandLine;
    private final static Options options;

    static {
        options = new Options();
        options.addOption(Option.builder().longOpt(ENV_OPT).
                hasArg().
                desc("Must be one of 'local', 'dev', 'prepdev', 'pilot' or 'production'").
                build());

        options.addOption(Option.builder().longOpt(INITIALISE_OPT).
                hasArg(false).
                desc("Initialise the trust anchor key pair and persist its state").
                build());

        options.addOption(Option.builder().longOpt(GENERATE_TA_CERTIFICATE_OPT).
                hasArg(false).
                desc("Generate trust anchor certificate and persist its state").
                build());

        options.addOption(Option.builder().longOpt(FORCE_NEW_TA_CERT_OPT).
            hasArg(false).
            desc("Force re-issuing new TA certificate if there're SIA differences between config and request").
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

        options.addOption(Option.builder().longOpt(STORAGE_DIRECTORY).
                hasArg(true).
                desc("Path to the persistent storage directory").
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
        if (!hasEnv() || !(
                hasInitialiseOption() || hasGenerateTACertificateOption() || hasExportCertificateOption() ||
                hasForceNewTaCertificate() || hasPrintTALOption() || hasRequestOption() || hasResponseOption()
        )) {
            throw new BadOptions("Doesn't have meaningful options.");
        }

        checkIncompatible(GENERATE_TA_CERTIFICATE_OPT, INITIALISE_OPT, PRINT_TAL_OPT, EXPORT_TA_CERTIFICATE_OPT);

        checkIncompatible(EXPORT_TA_CERTIFICATE_OPT, INITIALISE_OPT);

        checkIncompatible(PRINT_TAL_OPT, INITIALISE_OPT);

        checkIncompatible(REQUEST_OPT, INITIALISE_OPT, GENERATE_TA_CERTIFICATE_OPT, EXPORT_TA_CERTIFICATE_OPT, PRINT_TAL_OPT);

        checkIncompatible(EXPORT_TA_CERTIFICATE_OPT, PRINT_TAL_OPT);

        checkDependency(REQUEST_OPT, RESPONSE_OPT);

        checkDependency(RESPONSE_OPT, REQUEST_OPT);

        checkDependency(FORCE_NEW_TA_CERT_OPT, REQUEST_OPT, RESPONSE_OPT);
    }

    private void checkDependency(final String option, final String... dependencies) throws BadOptions {
        for (final String dependency : dependencies) {
            if (commandLine.hasOption(option) && !commandLine.hasOption(dependency)) {
                throw new BadOptions("Option --" + option + " doesn't make sense without --" + dependency + " option.");
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

    public boolean hasForceNewTaCertificate() {
        return commandLine.hasOption(FORCE_NEW_TA_CERT_OPT);
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

    public boolean hasGenerateTACertificateOption() {
        return commandLine.hasOption(GENERATE_TA_CERTIFICATE_OPT);
    }

    public boolean hasPersistentStoragePath() {
        return commandLine.hasOption(STORAGE_DIRECTORY);
    }

    public String getPersistentStoragePath() {
        return commandLine.getOptionValue(STORAGE_DIRECTORY);
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
