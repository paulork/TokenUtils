package br.com.paulork.tokenutils.exceptions;

public class PCryptException extends Exception {

    public PCryptException() {
    }

    public PCryptException(String msg) {
        super(msg);
    }

    public PCryptException(String msg, Throwable cause) {
        super(msg, cause);
    }
}
