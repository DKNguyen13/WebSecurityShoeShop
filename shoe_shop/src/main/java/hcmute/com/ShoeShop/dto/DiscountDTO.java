package hcmute.com.ShoeShop.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class DiscountDTO {
    private String name;
    private int quantity;
    private double percent;
    private String status;
    private Double minOrderValue;
    private String startDate;
    private String endDate;
    private String createdDate;
}
