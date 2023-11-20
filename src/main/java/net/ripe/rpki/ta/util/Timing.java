package net.ripe.rpki.ta.util;

import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;

public class Timing {
    static DateTime globalNow;

    // Since this program runs within a script, we can safely assume that all
    // calls to "now" can be replaced with a value calculated only once.
    public static synchronized DateTime now() {
        if (globalNow == null) {
            globalNow = DateTime.now(DateTimeZone.UTC);
        }
        return globalNow;
    }

}
