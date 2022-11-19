package rikkei.academy.service.song;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import rikkei.academy.model.User;
import rikkei.academy.model.song.Category;
import rikkei.academy.model.song.Song;
import rikkei.academy.repository.ISongRepository;
import rikkei.academy.security.userprincipal.UserDetailServiceIMPL;

import javax.transaction.Transactional;
import java.util.List;
import java.util.Optional;

@Service
public class SongServiceIMPL implements ISongService {
    @Autowired
    private ISongRepository songRepository;
    @Autowired
    private UserDetailServiceIMPL userDetailServiceIMPL;
    @Override
    public List<Song> findAll() {
        return songRepository.findAll();
    }

    @Override
    public Page<Song> findAll(Pageable pageable) {
        return songRepository.findAll(pageable);
    }

    @Override
    public Song save(Song song) {
        User user = userDetailServiceIMPL.getCurrentUser();
        song.setUser(user);
        return songRepository.save(song);
    }

    @Override
    public void deleteById(Long id) {
        songRepository.deleteById(id);
    }

    @Override
    public Optional<Song> findById(Long id) {
        return songRepository.findById(id);
    }


    @Override
    public Iterable<Song> findByCategory(Category category) {
        return songRepository.findByCategory(category);
    }

    @Override
    public List<Song> findByNameContaining(String name) {
        return songRepository.findByNameContaining(name);
    }

    @Override
    public Page<Song> findByNameContaining(String name, Pageable pageable) {
        return songRepository.findByNameContaining(name, pageable);
    }
}
