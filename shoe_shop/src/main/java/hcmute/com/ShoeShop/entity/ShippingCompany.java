package hcmute.com.ShoeShop.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Entity
@Data
public class ShippingCompany {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;

    @NotBlank(message = "Tên nhà vận chuyển không được để trống")
    @Size(min = 2, max = 50, message = "Tên nhà vận chuyển phải có độ dài từ 2 đến 50 ký tự")
    private String name; // Tên nhà vận chuyển

    @NotNull(message = "Phí vận chuyển không được để trống")
    @Min(value = 0, message = "Phí vận chuyển phải lớn hơn hoặc bằng 0")
    private int shippingFee; // Phí vận chuyển

    @NotNull(message = "Not null")
    private Boolean active = false; //true = active , false = inactive
}