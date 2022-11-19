package rikkei.academy.controller.song;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import rikkei.academy.dto.response.ResponseMessage;
import rikkei.academy.model.song.Singer;
import rikkei.academy.service.singer.ISingerService;

import java.util.Optional;

import static org.springframework.http.HttpStatus.NOT_FOUND;

@RestController
@RequestMapping("api/singer")
@CrossOrigin(origins = "*")
public class SingerController {
    @Autowired
    private ISingerService singerService;
    @GetMapping
    public ResponseEntity<?> findAllSinger(Pageable pageable){
        return ResponseEntity.ok(singerService.findAll(pageable));
    }
    @PostMapping
    public ResponseEntity<?> createSinger(@RequestBody Singer singer){
        if (singer.getName().trim().equals("")){
            return new ResponseEntity<>(new ResponseMessage("name_valid"),HttpStatus.NOT_FOUND);
        }
        singerService.save(singer);
        return new ResponseEntity<>(new ResponseMessage("Create_success"),HttpStatus.CREATED);
    }
    @DeleteMapping("{id}")
    public ResponseEntity<?> deleteSinger(@PathVariable("id")Singer singer){
        if(singer==null){
            return new ResponseEntity<>(NOT_FOUND);
        }
        singerService.deleteById(singer.getId());
        return new ResponseEntity<>(new ResponseMessage("delete_ok"),HttpStatus.OK);
    }
    @GetMapping("{id}")
    public ResponseEntity<?> getSinger(@PathVariable ("id") Singer singer){
        return singer== null ? new ResponseEntity<>(NOT_FOUND) : ResponseEntity.ok(singer);
    }
    @PutMapping("{id}")
    public ResponseEntity<?> editSinger(@PathVariable("id")Singer oldSinger,
                                        @RequestBody Singer newSinger){
        if (oldSinger==null) {
            return new ResponseEntity<>(NOT_FOUND);
        }
        oldSinger.setName(newSinger.getName());
        singerService.save(oldSinger);
        return ResponseEntity.ok(oldSinger);

    }
}
