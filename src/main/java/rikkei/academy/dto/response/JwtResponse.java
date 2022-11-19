package rikkei.academy.dto.response;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class JwtResponse {
    private String token;
    private String type = "Bearer";
    private String name;
    private  String avatar;
    private Collection<? extends GrantedAuthority> roles;

    public JwtResponse(String token, String name,String avatar, Collection<? extends GrantedAuthority> authorities) {
        this.token = token;
        this.name = name;
        this.avatar = avatar;
        this.roles = authorities;
    }
}
