package rikkei.academy.service.role;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import rikkei.academy.model.Role;
import rikkei.academy.model.RoleName;
import rikkei.academy.repository.IRoleRepository;

import java.util.Optional;

@Service
public class RoleServiceIMPL implements IRoleService{
    @Autowired
    private IRoleRepository roleRepository;
    @Override
    public Optional<Role> findByName(RoleName roleName) {
        return roleRepository.findByName(roleName);
    }

    @Override
    public Role findById(Long id) {
        return roleRepository.findById(id).get();
    }

}
