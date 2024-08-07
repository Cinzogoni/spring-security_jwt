package com.cinzogoni.springsecurity_jwt.controller;

import com.cinzogoni.springsecurity_jwt.dto.JwtAuthenticationResponse;
import com.cinzogoni.springsecurity_jwt.dto.RefreshTokenRequest;
import com.cinzogoni.springsecurity_jwt.dto.SignInRequest;
import com.cinzogoni.springsecurity_jwt.dto.SignUpRequest;
import com.cinzogoni.springsecurity_jwt.entities.User;
import com.cinzogoni.springsecurity_jwt.services.AuthenticationService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    private final AuthenticationService authenticationService;

    //Đăng ký
    @PostMapping("/signup")
    public ResponseEntity<User> signUp(@RequestBody SignUpRequest signUpRequest) {
        return ResponseEntity.ok(authenticationService.signUp(signUpRequest));
    }

    //Đăng nhập
    @PostMapping("/signin")
    public ResponseEntity<JwtAuthenticationResponse> signIn(@RequestBody SignInRequest signInRequest) {
        return ResponseEntity.ok(authenticationService.signIn(signInRequest));
    }

    /*
    Mục Đích Cung cấp trải nghiệm người dùng liền mạch:
    Cho phép người dùng duy trì phiên làm việc mà không phải đăng nhập lại khi token hiện tại hết hạn.
    Tăng cường bảo mật: Refresh token thường có thời gian sống dài hơn JWT và được sử dụng để yêu cầu JWT mới khi JWT hết hạn,
    giúp giảm thiểu sự phụ thuộc vào việc đăng nhập lại.
     */
    @PostMapping("/refresh")
    public ResponseEntity<JwtAuthenticationResponse> refresh(@RequestBody RefreshTokenRequest refreshTokenRequest) {
        return ResponseEntity.ok(authenticationService.refreshToken(refreshTokenRequest));
    }

}
