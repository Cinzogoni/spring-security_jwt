package com.cinzogoni.springsecurity_jwt.config;

import com.cinzogoni.springsecurity_jwt.entities.Role;
import com.cinzogoni.springsecurity_jwt.services.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final UserService userService;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http
                //Vô hiệu hóa bảo vệ CSRF (Cross-Site Request Forgery).
                .csrf(AbstractHttpConfigurer::disable)

                //Cấu hình các quy tắc ủy quyền cho các yêu cầu HTTP
                .authorizeHttpRequests(request -> request
                        .requestMatchers("api/v1/auth/**").permitAll()
                        .requestMatchers("api/v1/admin").hasAnyAuthority(Role.ADMIN.name())
                        .requestMatchers("api/v1/user").hasAnyAuthority(Role.USER.name())
                        .anyRequest().authenticated()
                )

                //Cấu hình quản lý phiên, đặt chính sách tạo phiên là STATELESS (không sử dụng phiên để lưu trạng thái)
                .sessionManagement(manager -> manager.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                //Tạo và cấu hình một đối tượng DaoAuthenticationProvider.
                .authenticationProvider(daoAuthenticationProvider())

                //Thêm bộ lọc JWT trước bộ lọc xác thực username và password.
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    //Được sử dụng để xác thực người dùng bằng cách sử dụng dịch vụ người dùng tùy chỉnh và bộ mã hóa mật khẩu.
    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider() {
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
        daoAuthenticationProvider.setUserDetailsService(userService.userDetailsService());
        daoAuthenticationProvider.setPasswordEncoder(passwordEncoder());
        return daoAuthenticationProvider;
    }

    //Được sử dụng để mã hóa mật khẩu
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    //Được sử dụng để quản lý xác thực
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration)
            throws Exception {
        return configuration.getAuthenticationManager();
    }
}
