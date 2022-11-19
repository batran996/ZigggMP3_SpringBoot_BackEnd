package rikkei.academy.repository;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import rikkei.academy.model.song.Category;
import rikkei.academy.model.song.Song;

import java.util.List;

@Repository
public interface ISongRepository extends JpaRepository<Song,Long> {
    Iterable<Song> findByCategory(Category category);
    List<Song> findByNameContaining(String name);
    Page<Song> findByNameContaining(String name, Pageable pageable);
}
