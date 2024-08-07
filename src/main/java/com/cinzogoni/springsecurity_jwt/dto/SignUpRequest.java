package com.cinzogoni.springsecurity_jwt.dto;

import lombok.Data;

@Data
public class SignUpRequest {
    private String fullName;
    private String email;
    private String password;
}
