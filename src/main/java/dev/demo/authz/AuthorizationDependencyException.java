package dev.demo.authz;

public final class AuthorizationDependencyException extends RuntimeException {
    public AuthorizationDependencyException(String message) {
        super(message);
    }
    public AuthorizationDependencyException(String message, Throwable cause) {
        super(message, cause);
    }
}
