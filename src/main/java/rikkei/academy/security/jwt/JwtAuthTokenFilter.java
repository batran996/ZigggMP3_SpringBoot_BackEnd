package rikkei.academy.security.jwt;
import org.springframework.web.filter.OncePerRequestFilter;
import rikkei.academy.security.userprincipal.UserDetailServiceIMPL;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import rikkei.academy.security.userprincipal.UserDetailServiceIMPL;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;



public class JwtAuthTokenFilter extends OncePerRequestFilter {
    @Autowired
    private JwtProvider tokenProvider;
    @Autowired
    private UserDetailServiceIMPL userDetailServiceIMPL;
    private static final Logger logger = LoggerFactory.getLogger(JwtAuthTokenFilter.class);
    //HÀM TIẾN HÀNH KIỂM TRA TOKEN HỢP LỆ VÀ SET USER VÀO authentication

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        try {
            String token = getJwt(request);
            if(token !=null &&tokenProvider.validateJwtToken(token)){
                String username = tokenProvider.getUserNameFromJwtToken(token);
                UserDetails userDetails = userDetailServiceIMPL.loadUserByUsername(username);
                UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities());
                authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            }
        } catch (Exception e){
            logger.error("Can't set user authentication -> Message: {}",e);
        }
        filterChain.doFilter(request,response);
    }
    private String getJwt(HttpServletRequest request){
        String authHeader = request.getHeader("Authorization");
        if(authHeader !=null && authHeader.startsWith("Bearer")){
            return authHeader.replace("Bearer", "");
        }
        return null;
    }
}
