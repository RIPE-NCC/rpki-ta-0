package net.ripe.rpki.ta.exception;

public class OperationAbortedException extends Exception {
    private static final long serialVersionUID = 1L;
    public OperationAbortedException(String message) {
        super(message);
    }
}
