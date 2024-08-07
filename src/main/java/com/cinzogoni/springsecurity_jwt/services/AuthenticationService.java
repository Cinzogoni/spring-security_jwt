package com.cinzogoni.springsecurity_jwt.services;

import com.cinzogoni.springsecurity_jwt.dto.JwtAuthenticationResponse;
import com.cinzogoni.springsecurity_jwt.dto.RefreshTokenRequest;
import com.cinzogoni.springsecurity_jwt.dto.SignInRequest;
import com.cinzogoni.springsecurity_jwt.dto.SignUpRequest;
import com.cinzogoni.springsecurity_jwt.entities.User;

public interface AuthenticationService {

    User signUp(SignUpRequest signUpRequest);

    JwtAuthenticationResponse signIn(SignInRequest signInRequest);

    JwtAuthenticationResponse refreshToken(RefreshTokenRequest refreshTokenRequest);
}
