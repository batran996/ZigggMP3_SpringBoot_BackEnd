package rikkei.academy.dto.request;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Set;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class UserDTO {
        private String name;
        private String username;
        private String email;
        private String password;
        private String avatar;
        private Set<String> roles;
}
