package net.ripe.rpki.ta.exception;

public class OperationAbortedException extends Exception {
    public OperationAbortedException(String message) {
        super(message);
    }
}
