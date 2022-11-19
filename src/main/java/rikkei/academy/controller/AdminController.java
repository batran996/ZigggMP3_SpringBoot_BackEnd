package rikkei.academy.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import rikkei.academy.dto.request.UserDTO;
import rikkei.academy.dto.response.ResponseMessage;
import rikkei.academy.model.Role;
import rikkei.academy.model.RoleName;
import rikkei.academy.model.User;
import rikkei.academy.repository.IUserRepository;
import rikkei.academy.service.role.IRoleService;
import rikkei.academy.service.user.IUSerService;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

@RestController
@CrossOrigin
@RequestMapping("/api/admin")
public class AdminController {
    @Autowired
    private IRoleService roleService;
    @Autowired
    IUSerService uSerService;
//    @Autowired
//    IUserRepository userRepository;
    @GetMapping("/listuser")
    public ResponseEntity<?> ShowListUser(@PageableDefault(size = 5) Pageable pageable) {
        Page<User> users = uSerService.findAll(pageable);
        return new ResponseEntity<>(users, HttpStatus.OK);
    }
    @PutMapping("/{id}")
    public ResponseEntity<?> editUser(
            @PathVariable
            Long id,
            @RequestBody
            UserDTO userDTO
    ) {
        Optional<User> userOptional = uSerService.findById(id);
        if (!userOptional.isPresent()) {
            return new ResponseEntity<>(new ResponseMessage("user not found!!!"), HttpStatus.NOT_FOUND);
        }

        User user = userOptional.get();
        user.setId(id);
        user.setName(userDTO.getName());
        user.setUsername(userDTO.getUsername());
        user.setEmail(userDTO.getEmail());
//        user.setAvatar(userDTO.getAvatar());

        Set<Role> roles = new HashSet<>();
        for (String idRole :
                userDTO.getRoles()) {
            Role userRole = roleService.findById(Long.parseLong(idRole));
            roles.add(userRole);
        }
//        Role userRole = roleService.findByName(RoleName.USER).orElseThrow(() -> new RuntimeException("not_found"));
        user.setRoles(roles);
        uSerService.save(user);
        return new ResponseEntity<>(new ResponseMessage("Edit user success!"), HttpStatus.OK);
    }
    @DeleteMapping("/{id}")
    public ResponseEntity<?> deleteById(
            @PathVariable("id") Optional<User> user
    ) {
        if(!user.isPresent()) {
            return new ResponseEntity<>(new ResponseMessage("user not found!!!"), HttpStatus.NOT_FOUND);
        }
        uSerService.deleteById(user.get().getId());
        return new ResponseEntity<>(new ResponseMessage("Delete success!!"), HttpStatus.OK);
    }
    @GetMapping("/{id}")
    public ResponseEntity<?> details(@PathVariable Long id) {
        Optional<User> user = uSerService.findById(id);
        if (!user.isPresent()) {
            return new ResponseEntity<>(new ResponseMessage("user not found!!!"), HttpStatus.NOT_FOUND);
        }
        return new ResponseEntity<>(user.get(), HttpStatus.OK);
    }
    @GetMapping("role")
    public  ResponseEntity<?> getRole(Long id){
        return new ResponseEntity<>(roleService.findById(id),HttpStatus.OK);
    }

}
