package com.security.amit.auth.controller;


import com.security.amit.auth.model.User;
import com.security.amit.auth.request.SignUpRequest;
import com.security.amit.auth.request.SigninRequest;
import com.security.amit.auth.response.JwtAuthenticationResponse;
import com.security.amit.auth.service.AuthenticationService;
import com.security.amit.exception.UserAlreadyExistsException;
import com.security.amit.exception.WrongCredentialException;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {
    private final AuthenticationService authenticationService;

    @PostMapping("/signup")
    public ResponseEntity<User> signup(@Valid @RequestBody SignUpRequest request) throws UserAlreadyExistsException {
        return ResponseEntity.ok(authenticationService.signup(request));
    }

    @PostMapping("/signin")
    public ResponseEntity<JwtAuthenticationResponse> signin(@Valid @RequestBody SigninRequest request) throws WrongCredentialException {
        return ResponseEntity.ok(authenticationService.signin(request));
    }
}
