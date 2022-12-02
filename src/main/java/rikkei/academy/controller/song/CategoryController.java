package rikkei.academy.controller.song;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import rikkei.academy.dto.response.ResponseMessage;
import rikkei.academy.model.song.Category;
import rikkei.academy.service.category.ICategoryService;

import java.util.Optional;

import static org.springframework.http.HttpStatus.*;

@RestController
@RequestMapping("/api/categories")
@CrossOrigin
public class CategoryController {
    @Autowired
    private ICategoryService categoryService;

    @GetMapping
    public ResponseEntity<?> getList(Pageable pageable) {
        return ResponseEntity.ok(categoryService.findAll(pageable));
    }

    @PostMapping
    public ResponseEntity<?> createCategory(
            @RequestBody
            Category category
    ) {
        if (category.getName().trim().equals("")) {
            return new ResponseEntity<>(new ResponseMessage("name_valid"), NOT_FOUND);
        }
        categoryService.save(category);
//        return new  ResponseEntity<>(new ResponseMessage("create success"), OK);
        return new ResponseEntity<>(category, OK);
    }

    @GetMapping("{id}")
    public ResponseEntity<?> findById(@PathVariable("id") Category category) {
        return category == null ? new ResponseEntity<>(NOT_FOUND) : ResponseEntity.ok(category);
    }

    @PutMapping("{id}")
    public ResponseEntity<?> updateCategory(
            @PathVariable("id") Long id,
            @RequestBody Category category
    ) {
        Optional<Category> optionalCategory = categoryService.findById(id);
        if (!optionalCategory.isPresent()) {
            return new ResponseEntity<>(NOT_FOUND);
        }
        category.setId(id);
        categoryService.save(category);
        return new ResponseEntity<>(new ResponseMessage("Update_success"), OK);
    }

    @DeleteMapping("{id}")
    public ResponseEntity<?> deleteCategory(
            @PathVariable("id") Category category
    ) {
        if (category == null) {
            return new ResponseEntity<>(NOT_FOUND);
        }
        categoryService.deleteById(category.getId());
        return ResponseEntity.ok(new ResponseMessage("delete"));
    }
}
