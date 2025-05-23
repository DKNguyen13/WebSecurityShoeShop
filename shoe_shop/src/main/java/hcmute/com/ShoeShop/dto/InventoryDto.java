package hcmute.com.ShoeShop.dto;
import lombok.Data;

import java.time.LocalDateTime;

@Data
public class InventoryDto {
    protected Long id;
    protected Long productDetailId;
    private String title;
    private int quantity;
    private int size;
    private LocalDateTime createdAt;
}
