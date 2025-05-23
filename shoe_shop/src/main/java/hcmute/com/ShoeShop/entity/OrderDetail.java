package hcmute.com.ShoeShop.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Entity
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class OrderDetail {
        @Id
        @GeneratedValue(strategy = GenerationType.IDENTITY)
        private int id;

        @ManyToOne
        @JoinColumn(name = "order_id", nullable = false)
        @NotNull(message = "Order cannot be null")
        private Order order;

        @ManyToOne
        @NotNull(message = "Product cannot be null")
        @JoinColumn(name = "productdetail_id", nullable = false)
        private ProductDetail product;

        @NotNull(message = "Quantity cannot be null")
        @PositiveOrZero(message = "Total price must be greater than or equal to 0")
        private int quantity;

        @NotNull(message = "Price cannot be null")
        @PositiveOrZero(message = "Total price must be greater than or equal to 0")
        private double price;
}
