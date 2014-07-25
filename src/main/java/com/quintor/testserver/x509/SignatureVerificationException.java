/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package com.quintor.testserver.x509;

/**
 *
 * @author rhegge
 */
public class SignatureVerificationException extends Exception {
    private static final long serialVersionUID = 1L;

    public SignatureVerificationException(String message, Throwable cause) {
        super(message, cause);
    }

    public SignatureVerificationException(String message) {
        super(message);
    }
}
