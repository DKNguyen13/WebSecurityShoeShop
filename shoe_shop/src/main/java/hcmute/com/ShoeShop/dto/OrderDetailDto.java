package hcmute.com.ShoeShop.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class OrderDetailDto {
        private String product_name;
        private int size;
        private String image;
        private int quantity;
        private double price;
        private double amount;
}
