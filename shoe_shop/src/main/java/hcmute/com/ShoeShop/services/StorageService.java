package hcmute.com.ShoeShop.services;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

@Service
@Slf4j
public class StorageService {

    // Đường dẫn tới thư mục uploads trong dự án
    private final String UPLOAD_DIR = System.getProperty("user.dir") + File.separator + "uploads"; // Đường dẫn tuyệt đối

    // Phương thức upload tệp tin
    public String uploadFile(MultipartFile file, String fileName) {
        // Tạo thư mục uploads nếu chưa tồn tại
        File uploadDir = new File(UPLOAD_DIR);
        if (!uploadDir.exists()) {
            if (!uploadDir.mkdirs()) { // Dùng mkdirs() để tạo các thư mục con nếu cần
                throw new RuntimeException("Failed to create upload directory");
            }
        }

        // Thay thế dấu ":" trong tên tệp bằng dấu "_" hoặc dấu khác
        String validFileName = sanitizeFileName(fileName);

        // Chuyển MultipartFile thành tệp File trong thư mục uploads
        File fileObj = new File(uploadDir, validFileName);
        try {
            // Lưu tệp vào thư mục uploads
            file.transferTo(fileObj);
        } catch (IOException e) {
            throw new RuntimeException("Failed to transfer file", e);
        }

        // Trả về đường dẫn URL tương đối để trình duyệt có thể sử dụng
        return "/images/" + validFileName;  // Đảm bảo đây là đường dẫn tương đối từ thư mục server public
    }


    // Phương thức để thay thế dấu ":" và các ký tự không hợp lệ trong tên tệp
    private String sanitizeFileName(String fileName) {
        // Thay thế tất cả dấu ":" thành dấu gạch ngang hoặc dấu khác
        return fileName.replace(":", "_").replaceAll("[^a-zA-Z0-9.-]", "_");
    }


}
