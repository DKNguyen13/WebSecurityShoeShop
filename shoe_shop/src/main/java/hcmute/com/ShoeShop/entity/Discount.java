package hcmute.com.ShoeShop.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDate;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Entity
public class Discount {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;

    @NotNull(message = "Name cannot be null")
    @Column(name = "name", nullable = false)
    private String name;

    @DecimalMin(value = "0.0", message = "Percent must be at least 0%")
    @DecimalMax(value = "100.0", message = "Percent cannot exceed 100%")
    @Column(name = "discount_percent", nullable = false)
    private double percent;

    @Column(length = 20)
    @NotNull(message = "Status cannot be null")
    private String status;


    @Column(name = "min_order_value")
    private Double minOrderValue;

    @Column(name = "created_date", nullable = false)
    private LocalDate createdDate;

    @Column(name = "start_date", nullable = false)
    @NotNull(message = "Start date cannot be null")
    private LocalDate startDate;

    @Column(name = "end_date", nullable = false)
    @NotNull(message = "End date cannot be null")
    @Future(message = "End date must be in the future")
    private LocalDate endDate;

    @PrePersist
    public void prePersist() {
        this.createdDate = LocalDate.now(); // Gán ngày tạo mặc định là hôm nay
    }
}
