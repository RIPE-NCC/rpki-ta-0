package net.ripe.rpki.ta.domain;


import org.joda.time.DateTime;

import java.math.BigInteger;

public class Revocation {

    private BigInteger serial;
    private DateTime notValidAfter;

    public BigInteger getSerial() {
        return serial;
    }

    public void setSerial(BigInteger serial) {
        this.serial = serial;
    }

    public DateTime getNotValidAfter() {
        return notValidAfter;
    }

    public void setNotValidAfter(DateTime notValidAfter) {
        this.notValidAfter = notValidAfter;
    }
}
