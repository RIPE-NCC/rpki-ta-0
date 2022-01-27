package net.ripe.rpki.ta.domain;


import lombok.Data;
import org.joda.time.DateTime;

import java.math.BigInteger;

@Data
public class Revocation {

    private BigInteger serial;
    private DateTime notValidAfter;
}
