package com.example.userauth2_0.dto;

import lombok.Data;
import lombok.NonNull;

import java.util.Set;

@Data
public class SignupDTO {
    private String username;
    private String password;
    private String firstname;
    private String lastname;
    private String email;
}
