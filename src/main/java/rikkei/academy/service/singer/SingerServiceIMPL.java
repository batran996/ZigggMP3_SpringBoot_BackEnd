package rikkei.academy.service.singer;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import rikkei.academy.model.song.Singer;
import rikkei.academy.repository.ISingerRepository;

import javax.transaction.Transactional;
import java.util.List;
import java.util.Optional;
@Service
public class SingerServiceIMPL implements ISingerService{
    @Autowired
    private ISingerRepository singerRepository;
    @Override
    public List<Singer> findAll() {
        return singerRepository.findAll();
    }

    @Override
    public Page<Singer> findAll(Pageable pageable) {
        return singerRepository.findAll(pageable);
    }

    @Override
    public Singer save(Singer singer) {
        return singerRepository.save(singer);
    }

    @Override
    public void deleteById(Long id) {
        singerRepository.deleteById(id);
    }

    @Override
    public Optional<Singer> findById(Long id) {
        return singerRepository.findById(id);
    }
}
