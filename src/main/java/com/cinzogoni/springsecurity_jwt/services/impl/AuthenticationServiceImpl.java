package com.cinzogoni.springsecurity_jwt.services.impl;

import com.cinzogoni.springsecurity_jwt.dto.JwtAuthenticationResponse;
import com.cinzogoni.springsecurity_jwt.dto.RefreshTokenRequest;
import com.cinzogoni.springsecurity_jwt.dto.SignInRequest;
import com.cinzogoni.springsecurity_jwt.dto.SignUpRequest;
import com.cinzogoni.springsecurity_jwt.entities.Role;
import com.cinzogoni.springsecurity_jwt.entities.User;
import com.cinzogoni.springsecurity_jwt.repository.UserRepository;
import com.cinzogoni.springsecurity_jwt.services.AuthenticationService;
import com.cinzogoni.springsecurity_jwt.services.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashMap;

/*
Chịu trách nhiệm xử lý các yêu cầu liên quan đến xác thực người dùng trong ứng dụng,
bao gồm đăng ký người dùng mới, đăng nhập người dùng, và tạo các token JWT cho xác thực và phân quyền.
 */
@Service
@RequiredArgsConstructor
public class AuthenticationServiceImpl implements AuthenticationService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;

    //Đăng ký người dùng mới.
    @Override
    public User signUp(SignUpRequest signUpRequest) {
        User user = new User();

        user.setFullName(signUpRequest.getFullName());
        user.setEmail(signUpRequest.getEmail());
        user.setRole(Role.USER);
        user.setPassword(passwordEncoder.encode(signUpRequest.getPassword()));

        return userRepository.save(user);
    }

    //Đăng nhập người dùng và tạo JWT.
    @Override
    public JwtAuthenticationResponse signIn(SignInRequest signInRequest) {

        //Xác thực người dùng bằng AuthenticationManager với tên người dùng và mật khẩu được cung cấp.
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(signInRequest.getEmail(), signInRequest.getPassword()));

        //Tìm người dùng trong cơ sở dữ liệu bằng email và ném lỗi nếu không tìm thấy.
        var user = userRepository.findByEmail(signInRequest.getEmail())
                .orElseThrow(() -> new IllegalArgumentException("Invalid email or password"));

        //Tạo token JWT và refresh token thông qua JwtService.
        var jwt = jwtService.generateToken(user);
        var refreshToken = jwtService.generateRefreshToken(new HashMap<>(), user);

        //Tạo đối tượng JwtAuthenticationResponse và thiết lập token và refresh token.
        JwtAuthenticationResponse jwtAuthenticationResponse = new JwtAuthenticationResponse();
        jwtAuthenticationResponse.setToken(jwt);
        jwtAuthenticationResponse.setRefreshToken(refreshToken);

        return jwtAuthenticationResponse;
    }

    //Xử lý yêu cầu làm mới token
    @Override
    public JwtAuthenticationResponse refreshToken(RefreshTokenRequest refreshTokenRequest) {

        //Trích xuất tên người dùng từ refresh token
        String userEmail = jwtService.extractUsername(refreshTokenRequest.getToken());
        User user = userRepository.findByEmail(userEmail).orElseThrow();

        //kiểm tra tính hợp lệ của refresh token
        if (jwtService.isTokenValid(refreshTokenRequest.getToken(), user)){

            //Tạo mới JWT
            var jwt = jwtService.generateToken(user);

            //Tạo và trả về phản hồi chứa token mới
            JwtAuthenticationResponse jwtAuthenticationResponse = new JwtAuthenticationResponse();
            jwtAuthenticationResponse.setToken(jwt);
            jwtAuthenticationResponse.setRefreshToken(refreshTokenRequest.getToken());

            return jwtAuthenticationResponse;
        }
        //Nếu refresh token không hợp lệ (không qua kiểm tra tính hợp lệ), phương thức trả về null.
        return null;
    }
}
