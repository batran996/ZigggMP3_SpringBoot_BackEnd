package rikkei.academy.service.song;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import rikkei.academy.model.song.Category;
import rikkei.academy.model.song.Song;
import rikkei.academy.service.IGenericService;

import java.util.List;

public interface ISongService extends IGenericService<Song> {
    Iterable<Song> findByCategory(Category category);
    List<Song> findByNameContaining(String name);
    Page<Song> findByNameContaining(String name, Pageable pageable);
}
