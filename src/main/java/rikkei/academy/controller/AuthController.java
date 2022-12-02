package rikkei.academy.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import rikkei.academy.dto.request.*;
import rikkei.academy.dto.response.JwtResponse;
import rikkei.academy.dto.response.ResponseMessage;
import rikkei.academy.model.Role;
import rikkei.academy.model.RoleName;
import rikkei.academy.model.User;
import rikkei.academy.security.jwt.JwtProvider;
import rikkei.academy.security.userprincipal.UserPrinciple;
import rikkei.academy.service.role.IRoleService;
import rikkei.academy.service.user.IUSerService;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

@RestController
@RequestMapping("/api/auth")
@CrossOrigin
public class AuthController {
    @Autowired
    private IRoleService roleService;
    @Autowired
    private IUSerService uSerService;
    @Autowired
    PasswordEncoder passwordEncoder;
    @Autowired
    JwtProvider jwtProvider;
    @Autowired
    private AuthenticationManager authenticationManager;

    @PostMapping("/signup")
    public ResponseEntity<?> signUp(@RequestBody SignUpForm signUpForm) {
        if (uSerService.existsByUsername(signUpForm.getUsername())) {
            return new ResponseEntity<>(new ResponseMessage("username_existed"), HttpStatus.OK);
        }
        if (uSerService.existsByEmail(signUpForm.getEmail())) {
            return new ResponseEntity<>(new ResponseMessage("email_existed"), HttpStatus.OK);
        }
//        Set<String> strRoles = signUpForm.getRoles();
        Set<Role> roles = new HashSet<>();
        Role roleSignUp = roleService.findByName(RoleName.USER).orElseThrow(() -> new RuntimeException("not_found"));
        roles.add(roleSignUp);

//        strRoles.forEach(role->{
//            switch (role.toLowerCase()){
//                case "admin":
//                    Role adminRole = roleService.findByName(RoleName.ADMIN).orElseThrow(()->new RuntimeException("not_found"));
//                    roles.add(adminRole);
//                    break;
//                case "pm":
//                    Role pmRole = roleService.findByName(RoleName.PM).orElseThrow(()->new RuntimeException("not_found"));
//                    roles.add(pmRole);
//                    break;
//                default:
//                    Role userRole = roleService.findByName(RoleName.USER).orElseThrow(()->new RuntimeException("not_found"));
//                    roles.add(userRole);
//
//            }
//        });
        User user = new User(signUpForm.getName(), signUpForm.getUsername(), signUpForm.getEmail(), passwordEncoder.encode(signUpForm.getPassword()), signUpForm.getAvatar(), roles);
        uSerService.save(user);
        return new ResponseEntity<>(new ResponseMessage("create_success"), HttpStatus.OK);
    }

    @PostMapping("/signin")
    public ResponseEntity<?> signIn(@Valid @RequestBody SignIn signIn) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(signIn.getUsername(), signIn.getPassword())
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String token = jwtProvider.generateJwtToken(authentication);
        UserPrinciple userPrinciple = (UserPrinciple) authentication.getPrincipal();
        return ResponseEntity.ok(new JwtResponse(token, userPrinciple.getName(), userPrinciple.getAvatar(), userPrinciple.getAuthorities()));
    }

    @GetMapping("/{id}")
    public ResponseEntity<?> details(@PathVariable Long id) {
        Optional<User> user = uSerService.findById(id);
        if (!user.isPresent()) {
            return new ResponseEntity<>(new ResponseMessage("user not found!!!"), HttpStatus.NOT_FOUND);
        }
        return new ResponseEntity<>(user.get(), HttpStatus.OK);
    }

    @GetMapping("/profile")
    public ResponseEntity<?> editUser() {

        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        return new ResponseEntity<>(principal, HttpStatus.OK);

    }

    @PutMapping("/changer/pass")
    public ResponseEntity<?> editPass(@RequestBody ChangerPassDTO changerPassDTO) {

        UserPrinciple userPrinciple = (UserPrinciple) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        String checkPass = userPrinciple.getPassword();

        if (!passwordEncoder.matches(changerPassDTO.getPassword(), checkPass)) {
            return new ResponseEntity<>(new ResponseMessage("Mật khẩu không đúng,vui lòng nhập lại !"),HttpStatus.NOT_FOUND);
        }
        if(!changerPassDTO.getNewPass().equals(changerPassDTO.getRePass())){
            return new ResponseEntity<>(new ResponseMessage("Mật khẩu mới không khớp,vui lòng nhập lại !"),HttpStatus.NOT_FOUND);
        }
        User user = uSerService.findByUsername(userPrinciple.getUsername()).get();
        user.setPassword(passwordEncoder.encode(changerPassDTO.getNewPass()));
        uSerService.save(user);
        return new ResponseEntity<>(new ResponseMessage("Changer pass success !"),HttpStatus.OK);
    }

    @PutMapping("/changer/avatar")
    public ResponseEntity<?>editAvatar(@RequestBody ChangeAvatar changeAvatar){
        UserPrinciple userPrinciple = (UserPrinciple) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        String username = userPrinciple.getUsername();
        User user = uSerService.findByUsername(username).get();
        user.setAvatar(changeAvatar.getAvatar());
        uSerService.save(user);
        return new ResponseEntity<>(new ResponseMessage("changer avatar success!"),HttpStatus.OK);
    }

}