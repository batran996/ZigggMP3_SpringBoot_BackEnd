package rikkei.academy.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import rikkei.academy.model.song.Category;
import rikkei.academy.model.song.Singer;


import java.util.List;

@Repository
public interface ICategoryRepository extends JpaRepository<Category,Long> {

}