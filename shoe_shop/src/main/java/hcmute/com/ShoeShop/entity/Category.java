package hcmute.com.ShoeShop.entity;

import jakarta.validation.constraints.*;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.ToString;

import jakarta.persistence.*;
import java.util.Set;

@Data
@Entity
@Table(name = "Category")
public class Category {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", nullable = false)
    protected Long id;

    @Basic
    @NotNull(message = "Type cannot be null")
    @Column(name = "type", nullable = true, length = 255, columnDefinition = "nvarchar(255)")
    private String type;

    @Size(max = 255, message = "Description cannot exceed 255 characters")
    @Column(name = "description", length = 255, columnDefinition = "nvarchar(255)")
    private String description;

    @OneToMany(mappedBy = "category", cascade = CascadeType.ALL)
    @EqualsAndHashCode.Exclude
    @ToString.Exclude
    private Set<Product> products;
}
