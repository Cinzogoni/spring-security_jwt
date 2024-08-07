package com.cinzogoni.springsecurity_jwt.services;

import com.cinzogoni.springsecurity_jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/*
Lớp CustomUserDetailsService cung cấp một cách để Spring Security truy xuất thông tin người dùng từ cơ sở dữ liệu.
Nó thực hiện việc tìm kiếm người dùng dựa trên tên người dùng và xử lý các tình huống khi người dùng không được tìm thấy.
Đây là một phần quan trọng trong hệ thống xác thực của ứng dụng, giúp xác định và xác thực người dùng khi họ đăng nhập.
 */

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) {
        return userRepository.findByEmail(username)
                .orElseThrow(() -> new UsernameNotFoundException("User Not Found"));
    }
}
