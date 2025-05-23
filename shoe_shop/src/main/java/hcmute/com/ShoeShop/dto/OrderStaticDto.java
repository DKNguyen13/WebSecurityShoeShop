package hcmute.com.ShoeShop.dto;

import lombok.Data;

@Data
public class OrderStaticDto {
        private long inStock;
        private long shipping;
        private long delivered;
        private long cancel;
        private long preturn;
}
