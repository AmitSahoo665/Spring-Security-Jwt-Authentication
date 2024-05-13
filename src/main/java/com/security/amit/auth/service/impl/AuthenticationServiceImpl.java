package com.security.amit.auth.service.impl;

import com.security.amit.auth.model.Role;
import com.security.amit.auth.model.User;
import com.security.amit.auth.repository.UserRepository;
import com.security.amit.auth.request.SignUpRequest;
import com.security.amit.auth.request.SigninRequest;
import com.security.amit.auth.response.JwtAuthenticationResponse;
import com.security.amit.auth.service.AuthenticationService;
import com.security.amit.exception.UserAlreadyExistsException;
import com.security.amit.exception.WrongCredentialException;
import com.security.amit.security.utility.JwtService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthenticationServiceImpl implements AuthenticationService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    public AuthenticationServiceImpl(UserRepository userRepository, PasswordEncoder passwordEncoder, JwtService jwtService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
    }

    @Override
    public User signup(SignUpRequest request) throws UserAlreadyExistsException {

        if (userRepository.findByEmail(request.getEmail()).isPresent())
            throw new UserAlreadyExistsException("User Already Exists with email ( " + request.getEmail() + " )");

        var user = User.builder().firstName(request.getFirstName()).lastName(request.getLastName())
                .email(request.getEmail()).password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER).build();
        return userRepository.save(user);
//        var jwt = jwtService.generateToken(user);
//        return JwtAuthenticationResponse.builder().token(jwt).build();
    }

    @Override
    public JwtAuthenticationResponse signin(SigninRequest request) throws WrongCredentialException {
        var user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new UsernameNotFoundException("Invalid email or password."));
        if (!passwordEncoder.matches(request.getPassword(), user.getPassword()))
            throw new WrongCredentialException("Wrong password !!!");
        var jwt = jwtService.generateToken(user);
        return JwtAuthenticationResponse.builder().token(jwt).build();
    }
}
