package com.security.amit.auth.service;


import com.security.amit.auth.model.User;
import com.security.amit.auth.request.SignUpRequest;
import com.security.amit.auth.request.SigninRequest;
import com.security.amit.auth.response.JwtAuthenticationResponse;
import com.security.amit.exception.UserAlreadyExistsException;
import com.security.amit.exception.WrongCredentialException;

public interface AuthenticationService {
    User signup(SignUpRequest request) throws UserAlreadyExistsException;

    JwtAuthenticationResponse signin(SigninRequest request) throws WrongCredentialException;
}
