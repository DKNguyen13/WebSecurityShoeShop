package hcmute.com.ShoeShop.dto;

import lombok.Data;

@Data
public class OrderPaymentDto {
        private double subtotal;
        private double discount;
        private double totalpay;
}
