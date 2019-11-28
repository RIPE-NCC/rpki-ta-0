package net.ripe.rpki.ta;


public class BadOptions extends Exception {
    public BadOptions(String message) {
        super(message);
    }

    public BadOptions(Exception e) {
        super(e);
    }
}
