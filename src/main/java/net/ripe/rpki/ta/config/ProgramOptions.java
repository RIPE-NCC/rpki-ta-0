package net.ripe.rpki.ta.config;


import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

public class ProgramOptions {

    public static final String INITIALISE_OPT = "initialise";

    private final Options options;
    private CommandLine commandLine;


    public ProgramOptions(String[] args) throws ParseException {
        options = new Options();
        options.addOption("initialise", "Initialise the trust ancor and persist it's state");
        commandLine = new DefaultParser().parse(options, args);
    }

    public boolean hasInitialise() {
        return commandLine.hasOption(INITIALISE_OPT);
    }
}
