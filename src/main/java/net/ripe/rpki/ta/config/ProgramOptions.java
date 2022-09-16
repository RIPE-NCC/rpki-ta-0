package net.ripe.rpki.ta.config;



import net.ripe.rpki.ta.exception.BadOptionsException;
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
    public static final String REVOKE_NON_REQUESTED_OBJECTS = "revoke-non-requested-objects";

    public static final String TA_CERTIFICATE_PUBLICATION_URI = "ta-certificate-publication-uri";
    public static final String TA_PRODUCTS_PUBLICATION_URI = "ta-products-publication-uri";
    public static final String NOTIFICATION_URI = "notification-uri";

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

        options.addOption(Option.builder().longOpt(REVOKE_NON_REQUESTED_OBJECTS)
                .hasArg(false)
                .desc("Revoke all objects that are not currently requested")
                .build()
        );

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

        options.addOption(Option.builder().longOpt(TA_CERTIFICATE_PUBLICATION_URI)
                .hasArg()
                .desc("Publication URI of this TA (only valid when initializing a new TA)")
                .build());
        options.addOption(Option.builder().longOpt(TA_PRODUCTS_PUBLICATION_URI)
                .hasArg()
                .desc("Publication URI for objects (only valid when initializing a new TA)")
                .build());
        options.addOption(Option.builder().longOpt(NOTIFICATION_URI)
                .hasArg()
                .desc("URI of the notification.xml in the RRDP repository (only valid when initializing a new TA)")
                .build());
    }

    public ProgramOptions(String... args) throws BadOptionsException {
        try {
            commandLine = new DefaultParser().parse(options, args);
        } catch (ParseException e) {
            throw new BadOptionsException(e);
        }
    }

    public void validateOptions() throws BadOptionsException {
        if (!hasEnv() || !(
                hasInitialiseOption() || hasGenerateTACertificateOption() || hasExportCertificateOption() ||
                hasForceNewTaCertificate() || hasPrintTALOption() || hasRequestOption() || hasResponseOption()
        )) {
            throw new BadOptionsException("Doesn't have meaningful options.");
        }

        checkIncompatible(GENERATE_TA_CERTIFICATE_OPT, INITIALISE_OPT, PRINT_TAL_OPT, EXPORT_TA_CERTIFICATE_OPT);

        checkIncompatible(EXPORT_TA_CERTIFICATE_OPT, INITIALISE_OPT);

        checkIncompatible(PRINT_TAL_OPT, INITIALISE_OPT);

        checkIncompatible(REQUEST_OPT, INITIALISE_OPT, GENERATE_TA_CERTIFICATE_OPT, EXPORT_TA_CERTIFICATE_OPT, PRINT_TAL_OPT);

        checkIncompatible(EXPORT_TA_CERTIFICATE_OPT, PRINT_TAL_OPT);

        checkDependency(REQUEST_OPT, RESPONSE_OPT);

        checkDependency(RESPONSE_OPT, REQUEST_OPT);

        checkDependency(FORCE_NEW_TA_CERT_OPT, REQUEST_OPT, RESPONSE_OPT);
        checkDependency(REVOKE_NON_REQUESTED_OBJECTS, REQUEST_OPT, RESPONSE_OPT);

        checkIncompatible(GENERATE_TA_CERTIFICATE_OPT, TA_CERTIFICATE_PUBLICATION_URI, TA_PRODUCTS_PUBLICATION_URI, NOTIFICATION_URI);
        checkIncompatible(PRINT_TAL_OPT, TA_CERTIFICATE_PUBLICATION_URI, TA_PRODUCTS_PUBLICATION_URI, NOTIFICATION_URI);
        checkIncompatible(EXPORT_TA_CERTIFICATE_OPT, TA_CERTIFICATE_PUBLICATION_URI, TA_PRODUCTS_PUBLICATION_URI, NOTIFICATION_URI);
    }

    private void checkDependency(final String option, final String... dependencies) throws BadOptionsException {
        for (final String dependency : dependencies) {
            if (commandLine.hasOption(option) && !commandLine.hasOption(dependency)) {
                throw new BadOptionsException("Option --" + option + " doesn't make sense without --" + dependency + " option.");
            }
        }
    }

    private void checkIncompatible(final String option, final String... incompatibleList) throws BadOptionsException {
        for (final String incompatibleOption : incompatibleList) {
            if (commandLine.hasOption(option) && commandLine.hasOption(incompatibleOption)) {
                throw new BadOptionsException("Cannot have both --" + option + " and --" + incompatibleOption + " options.");
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

    public boolean hasRevokeAllIssuedResourceCertificates() {
        return commandLine.hasOption(REVOKE_NON_REQUESTED_OBJECTS);
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

    public boolean hasTaCertificatePublicationUri() {
        return commandLine.hasOption(TA_CERTIFICATE_PUBLICATION_URI);
    }

    public String getTaCertificatePublicationUri() {
        return commandLine.getOptionValue(TA_CERTIFICATE_PUBLICATION_URI);
    }

    public boolean hasTaProductsPublicationUri() {
        return commandLine.hasOption(TA_PRODUCTS_PUBLICATION_URI);
    }

    public String getTaProductsPublicationUri() {
        return commandLine.getOptionValue(TA_PRODUCTS_PUBLICATION_URI);
    }

    public boolean hasNotificationUri() {
        return commandLine.hasOption(NOTIFICATION_URI);
    }

    public String getNotificationUri() {
        return commandLine.getOptionValue(NOTIFICATION_URI);
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
