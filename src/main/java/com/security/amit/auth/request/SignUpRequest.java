package com.security.amit.auth.request;


import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import jakarta.validation.constraints.NotBlank;


@Getter
@NoArgsConstructor
@AllArgsConstructor
public class SignUpRequest {
    @NotBlank(message = "firstname can not be empty or null")
    private String firstName;

    @NotBlank(message = "lastName can not be empty or null")
    private String lastName;

    @NotBlank(message = "email can not be empty or null")
    private String email;

    @NotBlank(message = "password can not be empty or null")
    private String password;
}
