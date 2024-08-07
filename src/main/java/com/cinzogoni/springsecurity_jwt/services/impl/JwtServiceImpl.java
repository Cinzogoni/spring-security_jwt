package com.cinzogoni.springsecurity_jwt.services.impl;


import com.cinzogoni.springsecurity_jwt.services.JwtService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.Map;
import java.util.function.Function;

/* Cung cấp các chức năng chính để tạo,
xác thực và trích xuất thông tin từ JWT trong một ứng dụng bảo mật */
@Service
public class JwtServiceImpl implements JwtService {

    /* JWT (JSON Web Token) là một tiêu chuẩn mở (RFC 7519)
    định nghĩa cách thức an toàn để truyền tải thông tin giữa các bên dưới dạng đối tượng JSON.
    JWT thường được sử dụng trong xác thực và phân quyền trong các ứng dụng web và dịch vụ API. */


    //Tạo JWT dựa trên thông tin của người dùng
    @Override
    public String generateToken(UserDetails userDetails) {
        return Jwts.builder()
                .setSubject(userDetails.getUsername()) //Tên người dùng (username)
                .setIssuedAt(new Date(System.currentTimeMillis())) //Thời điểm phát hành token
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 24)) //Thời điểm token hết hạn
                .signWith(getSiginKey(), SignatureAlgorithm.HS256) //Ký token bằng khóa bảo mật và thuật toán HMAC SHA-256
                .compact();
    }

    //được sử dụng để thực hiện xác thực và có thể được sử dụng để lấy một token mới khi token hiện tại hết hạn
    @Override
    public String generateRefreshToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        return Jwts.builder()
                /*
                Thiết lập các claims bổ sung cho token. Claims là thông tin mà bạn muốn đưa vào token.
                extraClaims là một bản đồ (map) chứa các dữ liệu bổ sung
                (như thông tin người dùng, quyền hạn, hoặc bất kỳ thông tin nào khác).
                 */
                .setClaims(extraClaims)
                /*
                Thiết lập tên người dùng (username) làm subject của token.
                Subject thường là thông tin nhận diện chính (như tên người dùng) của token.
                 */
                .setSubject(userDetails.getUsername()) //Tên người dùng (username)
                /*
                Thiết lập thời điểm token được phát hành. Đây là thời điểm hiện tại
                 */
                .setIssuedAt(new Date(System.currentTimeMillis()))
                /*
                Thiết lập thời điểm hết hạn của token.
                Trong trường hợp này, token sẽ hết hạn sau 7 ngày (604800000 milliseconds).
                 */
                .setExpiration(new Date(System.currentTimeMillis() + 604800000))
                .signWith(getSiginKey(), SignatureAlgorithm.HS256) //Ký token bằng khóa bảo mật và thuật toán HMAC SHA-256
                .compact();
    }

    //Trích xuất tên người dùng từ JWT
    @Override
    public String extractUsername(String token) {
        return extractClaims(token, Claims::getSubject);
    }

    //Lấy khóa ký từ chuỗi mã hóa bí mật
    private Key getSiginKey() {
        //Khóa bí mật để ký token
        String SECRET_KEY = "GkchwAQiUM0UN2sUtzeKzHYJ4Fh48w5V+Y7Jngdv56tQ29moXUysaXDshv7vzCGN7l4SlyFRAO0j2Xgwiwnuqg==";
        //Giải mã khóa bí mật từ Base64
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        //Tạo khóa sử dụng thuật toán HMAC SHA-256.
        return Keys.hmacShaKeyFor(keyBytes);
    }

    //Trích xuất các thông tin từ JWT
    private <T> T extractClaims(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token); //JWT cần trích xuất
        return claimsResolver.apply(claims); //Hàm xử lý các thông tin (Claims)
    }

    //Trích xuất tất cả các thông tin (Claims) từ JWT.
    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder() //Tạo JWT parser
                .setSigningKey(getSiginKey()) //Đặt khóa ký.
                .build().parseClaimsJws(token) //Phân tích JWT và lấy nội dung
                .getBody();
    }

    //Kiểm tra tính hợp lệ của JWT
    @Override
    public boolean isTokenValid(String token, UserDetails userDetails) {
        /* Kiểm tra tên người dùng trong token có khớp với tên người dùng trong UserDetails
           Kiểm tra token có hết hạn không. */
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    //Kiểm tra token có hết hạn không.
    private boolean isTokenExpired(String token) {
        //Trích xuất thời gian hết hạn từ JWT và so sánh với thời gian hiện tại
        return extractClaims(token, Claims::getExpiration).before(new Date());
    }
}
