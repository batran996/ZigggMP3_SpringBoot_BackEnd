package rikkei.academy.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import rikkei.academy.model.song.Singer;

import java.util.Optional;
@Repository
public interface ISingerRepository extends JpaRepository<Singer,Long> {
}
