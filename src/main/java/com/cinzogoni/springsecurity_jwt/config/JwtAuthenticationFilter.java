package com.cinzogoni.springsecurity_jwt.config;

import com.cinzogoni.springsecurity_jwt.services.JwtService;
import com.cinzogoni.springsecurity_jwt.services.UserService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;

/* Mục đích: Đoạn code này giúp kiểm tra và xác thực token JWT trong các yêu cầu HTTP
   để đảm bảo rằng chỉ những người dùng hợp lệ mới có thể truy cập vào các tài nguyên bảo mật */
@Component
@RequiredArgsConstructor
/* JwtAuthenticationFilter kế thừa từ OncePerRequestFilter,
nghĩa là nó sẽ được thực hiện một lần cho mỗi yêu cầu HTTP */
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserService userService;

    @Override
    //Phương thức chính thực hiện lọc yêu cầu. Nó được gọi cho mỗi yêu cầu HTTP.
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain)
            throws ServletException, IOException {

        /* Lấy tiêu đề Authorization từ yêu cầu HTTP.
        Kiểm tra xem tiêu đề có bắt đầu bằng Bearer không và có tồn tại không.
        Nếu không, tiếp tục xử lý yêu cầu mà không thực hiện xác thực JWT.
        Nếu có, lấy phần JWT từ tiêu đề và trích xuất tên người dùng từ JWT bằng cách sử dụng JwtService */
        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String userEmail;

        if (StringUtils.isEmpty(authHeader) || !org.apache.commons.lang3.StringUtils.startsWithIgnoreCase(authHeader, "Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }
        jwt = authHeader.substring(7);
        userEmail = jwtService.extractUsername(jwt);

        /*  Kiểm tra nếu userEmail rỗng hoặc chưa có xác thực trong SecurityContext.
            Tải thông tin người dùng từ cơ sở dữ liệu bằng cách sử dụng UserService.
            Xác thực token bằng JwtService.
            Nếu token hợp lệ, tạo một đối tượng UsernamePasswordAuthenticationToken với thông tin người dùng và các quyền của họ.
            Thiết lập đối tượng UsernamePasswordAuthenticationToken vào SecurityContext để thông báo với Spring Security rằng người dùng đã được xác thực.
         */
        if (!StringUtils.isEmpty(userEmail) && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = userService.userDetailsService().loadUserByUsername(userEmail);

            if (jwtService.isTokenValid(jwt, userDetails)) {
                SecurityContext securityContext = SecurityContextHolder.createEmptyContext();

                UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities()
                );
                token.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                securityContext.setAuthentication(token);
                SecurityContextHolder.setContext(securityContext);
            }
        }

        /*Sau khi thực hiện xác thực (hoặc nếu không cần xác thực),
          tiếp tục xử lý yêu cầu bằng cách gọi filterChain.doFilter(). */
        filterChain.doFilter(request, response);
    }
}
