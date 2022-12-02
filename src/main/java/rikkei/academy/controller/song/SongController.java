package rikkei.academy.controller.song;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import rikkei.academy.dto.request.SongDTO;
import rikkei.academy.dto.response.ResponseMessage;

//import rikkei.academy.dto.response.SongResponse;
import rikkei.academy.model.User;
import rikkei.academy.model.song.Category;
import rikkei.academy.model.song.Singer;
import rikkei.academy.model.song.Song;
import rikkei.academy.security.userprincipal.UserDetailServiceIMPL;
import rikkei.academy.security.userprincipal.UserPrinciple;
import rikkei.academy.service.category.ICategoryService;
import rikkei.academy.service.singer.ISingerService;
import rikkei.academy.service.song.ISongService;
import rikkei.academy.service.user.IUSerService;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;

@RestController
@RequestMapping("/api/song")
@CrossOrigin
public class SongController {
    @Autowired
    private ISongService songService;
    @Autowired
    private ICategoryService categoryService;
    @Autowired
    private ISingerService singerService;
    @Autowired
    private UserDetailServiceIMPL userDetailServiceIMPL;
    @Autowired
    private IUSerService uSerService;

    @GetMapping
    public ResponseEntity<?> findAllSong(@PageableDefault(size = (9)) Pageable pageable) {
        Page<Song> songs = songService.findAll(pageable);
        return new ResponseEntity<>(songs, HttpStatus.OK);
    }

    @PostMapping
    public ResponseEntity<?> createSong(@RequestBody Song song) {
//        UserPrinciple userPrinciple = (UserPrinciple) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
//        User user = uSerService.findByUsername(userPrinciple.getUsername()).get();
        User user = userDetailServiceIMPL.getCurrentUser();
        song.setUser(user);
        songService.save(song);
        return new ResponseEntity<>(new ResponseMessage("Create song success!"), HttpStatus.OK);
    }

    @PutMapping("/{id}")
    public ResponseEntity<?> editSong(@PathVariable Long id, @RequestBody SongDTO songDTO) {
        Optional<Song> songOptional = songService.findById(id);
        if (!songOptional.isPresent()) {
            return new ResponseEntity<>(new ResponseMessage("Song not found!"), HttpStatus.NOT_FOUND);
        }

        Song oldSong = songService.findById(id).get();
        oldSong.setName(songDTO.getName());

        songService.save(oldSong);
        return new ResponseEntity<>(new ResponseMessage("Edit song success!"), HttpStatus.OK);
    }

    @GetMapping("/{id}")
    public ResponseEntity<?> details(@PathVariable Long id) {
        Optional<Song> song = songService.findById(id);
        if (!song.isPresent()) {
            return new ResponseEntity<>(new ResponseMessage("Song not found"), HttpStatus.NOT_FOUND);
        }
        return new ResponseEntity<>(song.get(), HttpStatus.OK);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<?> deleteById(@PathVariable("id") Optional<Song> song) {
        if (!song.isPresent()) {
            return new ResponseEntity<>(new ResponseMessage("Song not found"), HttpStatus.NOT_FOUND);
        }
        songService.deleteById(song.get().getId());
        return new ResponseEntity<>(new ResponseMessage("Delete success!!"), HttpStatus.OK);
    }

    @GetMapping("/searchByName")
    public ResponseEntity<?> searchByName(@RequestParam String name) {

        return new ResponseEntity<>(songService.findByNameContaining(name), HttpStatus.OK);
    }

    @GetMapping("/search/page")
    public ResponseEntity<?> searchPageSong(@RequestParam String name, Pageable pageable) {
        return new ResponseEntity<>(songService.findByNameContaining(name, pageable), HttpStatus.OK);
    }
//    @GetMapping ("/searchByCategory/{name}")
//    public ResponseEntity<?> searchByCategory(@PathVariable("name") String name) {
//        return new ResponseEntity<>(categoryService.findByNameContaining(name), HttpStatus.OK);
//    }
//@GetMapping("/list")
//public ResponseEntity<?> listSong() {
//    List<SongResponse> listSongRes= new ArrayList<>();
//    SongResponse songResponse1= new SongResponse("1","1","1","1");
//    listSongRes.add(songResponse1);
//    return new ResponseEntity<>(listSongRes, HttpStatus.OK);
//}
}
