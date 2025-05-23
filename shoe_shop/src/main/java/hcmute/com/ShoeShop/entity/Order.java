package hcmute.com.ShoeShop.entity;

import hcmute.com.ShoeShop.utlis.PayOption;
import hcmute.com.ShoeShop.utlis.ShipmentStatus;
import jakarta.persistence.*;
import jakarta.validation.constraints.*;
import lombok.*;

import java.util.Date;
import java.util.Set;

@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "Orders")
@Builder
public class Order {
        @Id
        @GeneratedValue(strategy = GenerationType.IDENTITY)
        private long id;

        @ManyToOne
        @NotNull(message = "User cannot be null")
        @JoinColumn(name = "user_id", nullable = false) // Khóa ngoại đến User
        private Users user;

        @Column(name = "total_price", nullable = false)
        @NotNull(message = "Total price cannot be null")
        @PositiveOrZero(message = "Total price must be greater than or equal to 0")
        private Double totalPrice;

        @Column(name = "created_date", nullable = false)
        @Temporal(TemporalType.TIMESTAMP) // Định dạng DateTime
        @NotNull(message = "Created date cannot be null")
        private Date createdDate;

        @Enumerated(EnumType.STRING)
        @Column(name = "status", columnDefinition = "ENUM('IN_STOCK', 'SHIPPED', 'DELIVERED', 'CANCEL', 'RETURN')", nullable = false)
        private ShipmentStatus status;

        @OneToMany(mappedBy = "order",cascade = CascadeType.ALL)
        @EqualsAndHashCode.Exclude
        @ToString.Exclude
        private Set<OrderDetail> orderDetailSet;

        @Enumerated(EnumType.STRING)
        @Column(name = "pay_option", columnDefinition = "ENUM('COD', 'VNPAY')", nullable = false)
        private PayOption payOption;

        private String address;
}
