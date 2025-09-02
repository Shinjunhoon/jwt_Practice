package com.example.jwt_practice.Security.util;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;



@Component
public class JwtTokenUtil {
    private final SecretKey key; // SecretKey 타입으로 변경
    private final long expiration;


    public JwtTokenUtil(@Value("${jwt.secret}") String secretString,
                        @Value("${jwt.expiration}") long expiration) {


        // 인코딩된 BASE64URL -> 이진 데이터로 디코딩 작업
        byte[] keyBytes = Decoders.BASE64URL.decode(secretString);

        // 디코딩 된 배열을 secretKey  등록
        this.key = Keys.hmacShaKeyFor(keyBytes);

        this.expiration = expiration;
    }

    //
    public String generateToken(UserDetails userDetails) {
        return Jwts.builder()
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + expiration * 1000))
                .signWith(this.key) // SecretKey 객체 사용 알고리즘을 명시하지 않아도 Key의 바이트 길이를 확인하여 매칭되는 알고리즘을 자동으로 적용해준다.
                .compact();
    }

    // 토큰에서 유저 이름을 가져온더.
    public String getUsernameFromToken(String token) {
        return getClaimsFromToken(token).getSubject();
    }

    // 토큰이 유효한지 확인한다.
    public Boolean validateToken(String token, UserDetails userDetails) {
        final String userName = getUsernameFromToken(token);
        return userName.equals(userDetails.getUsername()) && !isTokenExpired(token);
    }
    // 토큰이 기간이 유효한지 확인한다.
    private Boolean isTokenExpired(String token){
        final Date expirationDate = getClaimsFromToken(token).getExpiration();
        return expirationDate.before(new Date());
    }

    // SecretKey을 통해 토큰을 파싱해 Claims을 가져온다.
    private Claims getClaimsFromToken(String token){
        // 미리 생성해둔 SecretKey 객체를 사용하여 검증
        return Jwts.parserBuilder()
                .setSigningKey(this.key)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}