package com.security.amit.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(value = HttpStatus.FORBIDDEN)
public class WrongCredentialException extends Exception {
    public WrongCredentialException(String message){
        super(message);
    };

}
