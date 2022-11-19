package rikkei.academy.model.song;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import rikkei.academy.model.User;

import javax.persistence.*;
import javax.validation.constraints.NotBlank;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

@Entity
@Table(name = "song")
@Data
@AllArgsConstructor
@NoArgsConstructor
public class Song {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Lob
    private String background;
    @NotBlank
    private String name;
    @Lob
    private String pathSong;
    @NotBlank
    private String duration;
    @ManyToOne
    private User user;
    @ManyToOne
    private Category category;
    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(name = "song_singer",
            joinColumns = @JoinColumn(name = "song_id"),inverseJoinColumns = @JoinColumn(name = "singer_id")
    )
    List<Singer> singers = new ArrayList<>();
}
