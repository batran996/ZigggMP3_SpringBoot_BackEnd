package rikkei.academy.service;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.util.List;
import java.util.Optional;

public interface IGenericService <T>{
    List<T> findAll();
    Page<T> findAll(Pageable pageable);
    T save(T t);
    void deleteById(Long id);
    Optional<T> findById(Long id);
}
