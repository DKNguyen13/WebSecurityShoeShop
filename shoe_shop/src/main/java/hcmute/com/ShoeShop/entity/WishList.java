package hcmute.com.ShoeShop.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Entity
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "wishlist")
public class WishList {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;

    @NotNull(message = "User must not be null")
    @ManyToOne
    @JoinColumn(name = "user_id", nullable = false)
    private Users user; // Mối quan hệ với Users

    @NotNull(message = "Product must not be null")
    @ManyToOne
    @JoinColumn(name = "product_id", nullable = false)
    private Product product; // Mối quan hệ với Product
}
