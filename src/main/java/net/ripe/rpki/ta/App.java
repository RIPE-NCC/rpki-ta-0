package net.ripe.rpki.ta;

import net.ripe.rpki.ta.config.ProgramOptions;
import org.apache.commons.cli.ParseException;

import javax.security.auth.x500.X500Principal;
import java.net.URI;

public class App
{
    public static void main( String[] args )
    {
        try {
            final ProgramOptions clOptions = new ProgramOptions(args);
            if (clOptions.hasInitialise()) {
                initialiseTa(clOptions);
            } else {
                // TODO Implement other options
            }
        } catch (ParseException e) {
            e.printStackTrace();
        }

        System.out.println( "I am the TA application" );
    }

    private static void initialiseTa(ProgramOptions clOptions) {
//        KeyHandlingDetails keyHandlingDetails = new KeyHandlingDetails(options.getKeyPairGeneratorProvider(), keyStoreProvider, keyStoreType, signatureProvider);
//        TrustAnchorDetails trustAnchorDetails = new TrustAnchorDetails(new X500Principal("CN=" + trustAnchorName), URI.create(trustAnchorCertificatePublicationUri), URI.create(trustAnchorProductsPublicationUri));
//
//        createAndStoreTrustAnchor(keyHandlingDetails, trustAnchorDetails);
    }
}
