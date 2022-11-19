package rikkei.academy.dto.request;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Set;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class SignUpForm {
    private String name;
    private String username;
    private String email;
    private String password;
    private String avatar = "https://vnn-imgs-f.vgcloud.vn/2020/03/23/11/trend-avatar-1.jpg";
//    private Set<String> roles;
}
