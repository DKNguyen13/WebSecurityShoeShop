package hcmute.com.ShoeShop.dto;

import hcmute.com.ShoeShop.utlis.PayOption;
import lombok.Builder;
import lombok.Data;

import java.util.Date;

@Data
@Builder
public class OrderDto {
    private int orderId;
    private Date createdDate;
    private String fullname;
    private double price;
    private String payOption;
    private String orderStatus;
}
