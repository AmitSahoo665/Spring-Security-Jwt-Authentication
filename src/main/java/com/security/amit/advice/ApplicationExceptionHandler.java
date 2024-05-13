package com.security.amit.advice;


import com.security.amit.exception.UserAlreadyExistsException;
import com.security.amit.exception.WrongCredentialException;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice
public class ApplicationExceptionHandler {
    private static final String MESSAGE_KEY = "message";

    @ResponseStatus(HttpStatus.FORBIDDEN)
    @ExceptionHandler(WrongCredentialException.class)
    public Map<String , String > handleWrongCredentialException(WrongCredentialException ex){
        Map<String , String > message = new HashMap<>();
        message.put(MESSAGE_KEY, ex.getMessage());
        return message;
    }

    @ResponseStatus(HttpStatus.CONFLICT)
    @ExceptionHandler(UserAlreadyExistsException.class)
    public Map<String , String > handleUserAlreadyExistsException(UserAlreadyExistsException ex){
        Map<String , String > message = new HashMap<>();
        message.put(MESSAGE_KEY, ex.getMessage());
        return message;
    }
}
