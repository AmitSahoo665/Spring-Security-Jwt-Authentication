package com.security.amit.auth.request;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;

@Getter
@NoArgsConstructor
@AllArgsConstructor
public class SigninRequest {
    @NotBlank(message = "email can not be empty or null")
    private String email;

    @NotBlank(message = "password can not be empty or null")
    private String password;
}
