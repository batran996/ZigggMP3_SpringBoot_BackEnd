package rikkei.academy.service.user;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import rikkei.academy.model.User;

import java.util.List;
import java.util.Optional;

public interface IUSerService {
    Boolean existsByUsername(String user);
    Boolean existsByEmail(String email);
    void save(User user);
    Optional<User> findByUsername(String username);
    List<User> findAll();
    Page<User> findAll(Pageable pageable);

    Optional<User> findById(Long id);

    void deleteById(Long id);
}
