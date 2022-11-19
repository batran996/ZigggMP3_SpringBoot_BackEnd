package rikkei.academy.security.jwt;


import io.jsonwebtoken.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import rikkei.academy.security.userprincipal.UserPrinciple;

import java.util.Date;

@Component
public class JwtProvider {
    //LỚP Logger giúp ta ghi log bắt các trường hợp ngoại lệ
    private static final Logger logger = LoggerFactory.getLogger(JwtProvider.class);
    private String jwtSecret="jwt.chinh.duong";



    private int jwtExpiration = 86400; //Set thời gian sống cho token
    //HÀM TIẾN HÀNH MÃ HÓA USER THÀNH CHUỖI TOKEN -> SẼ ĐƯỢC GỌI TẠI API LOGIN TRÊN CONTROLLER
    public String generateJwtToken(Authentication authentication) {

        UserPrinciple userPrincipal = (UserPrinciple) authentication.getPrincipal();

        return Jwts.builder()
                .setSubject((userPrincipal.getUsername()))
                .setIssuedAt(new Date())
                .setExpiration(new Date(new Date().getTime() + jwtExpiration * 1000))
                .signWith(SignatureAlgorithm.HS512, jwtSecret)
                .compact();
    }
    //HÀM TIẾN HAH KIỂM TRA TÍNH HỢP LỆ CỦA TOKEN ĐANG ĐĂNG NHẬP
    public boolean validateJwtToken(String authToken) {
        try {
            Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(authToken);
            return true;
        } catch (SignatureException e) {
            logger.error("Invalid JWT signature -> Message: {} ", e);
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token -> Message: {}", e);
        } catch (ExpiredJwtException e) {
            logger.error("Expired JWT token -> Message: {}", e);
        } catch (UnsupportedJwtException e) {
            logger.error("Unsupported JWT token -> Message: {}", e);
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty -> Message: {}", e);
        }

        return false;
    }
    //Lay lai thong nguoi dung tu chinh Token tao ra
    public String getUserNameFromJwtToken(String token) {

        String userName = Jwts.parser()
                .setSigningKey(jwtSecret)
                .parseClaimsJws(token)
                .getBody().getSubject();
        return userName;
    }
}
