package br.com.paulork.tokenutils.exceptions;

public class PSegredoException extends Exception {

    public PSegredoException() {
    }

    public PSegredoException(String msg) {
        super(msg);
    }

    public PSegredoException(String msg, Throwable cause) {
        super(msg, cause);
    }
}
