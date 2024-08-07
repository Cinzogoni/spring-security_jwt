package com.cinzogoni.springsecurity_jwt.services.impl;

import com.cinzogoni.springsecurity_jwt.services.CustomUserDetailsService;
import com.cinzogoni.springsecurity_jwt.services.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

/*
Lớp UserServiceImpl cung cấp một lớp dịch vụ đơn giản
để trả về một đối tượng UserDetailsService thông qua việc sử dụng CustomUserDetailsService.

Mục đích chính của lớp này là để đóng vai trò là lớp trung gian,
cung cấp cách truy xuất thông tin người dùng cho các phần khác của ứng dụng.
 */

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final CustomUserDetailsService customUserDetailsService;

    @Override
    public UserDetailsService userDetailsService() {
        return customUserDetailsService;
    }


}
