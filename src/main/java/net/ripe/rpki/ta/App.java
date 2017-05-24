package net.ripe.rpki.ta;

import net.ripe.rpki.ta.config.ProgramOptions;
import org.apache.commons.cli.ParseException;

import javax.security.auth.x500.X500Principal;
import java.net.URI;

public class App {
    public static void main(String[] args) {
        try {
            final ProgramOptions clOptions = new ProgramOptions(args);
            if (clOptions.hasAnyMeaningfulOption()) {
                System.err.println(clOptions.getUsageString());
                System.exit(1);
            }
            if (clOptions.hasInitialise()) {
                initialiseTa(clOptions);
            }
            // TODO Implement other options
        } catch (ParseException e) {
            System.err.println("The following problem occured: " + e.getMessage());
            e.printStackTrace(System.err);
            System.exit(2);
        }

        System.out.println("I am the TA application");
    }

    private static void initialiseTa(ProgramOptions clOptions) {
//        KeyHandlingDetails keyHandlingDetails = new KeyHandlingDetails(options.getKeyPairGeneratorProvider(), keyStoreProvider, keyStoreType, signatureProvider);
//        TrustAnchorDetails trustAnchorDetails = new TrustAnchorDetails(new X500Principal("CN=" + trustAnchorName), URI.create(trustAnchorCertificatePublicationUri), URI.create(trustAnchorProductsPublicationUri));
//
//        createAndStoreTrustAnchor(keyHandlingDetails, trustAnchorDetails);
    }
}
