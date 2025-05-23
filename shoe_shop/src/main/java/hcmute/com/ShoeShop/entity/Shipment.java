package hcmute.com.ShoeShop.entity;

import jakarta.validation.constraints.*;
import jakarta.persistence.*;
import lombok.Data;

import java.util.Date;

@Entity
@Data
public class Shipment {
        @Id
        @GeneratedValue(strategy = GenerationType.IDENTITY)
        private int id;

        @OneToOne
        @JoinColumn(name = "order_id", referencedColumnName = "id", nullable = false)
        @NotNull(message = "Order cannot be null")
        private Order order;

        @ManyToOne
        @JoinColumn(name = "shipper_id", referencedColumnName = "id", nullable = false)
        @NotNull(message = "Shipper must not be null")
        private Users shipper;

        @Column(name = "updated_date")
        private Date updatedDate;

        private String note;
}