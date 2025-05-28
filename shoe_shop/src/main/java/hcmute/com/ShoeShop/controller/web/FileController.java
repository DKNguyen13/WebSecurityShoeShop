package hcmute.com.ShoeShop.controller.web;

import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

@RestController
public class FileController {
    private final String UPLOAD_DIR = System.getProperty("user.dir") + File.separator + "uploads";

    // Danh sách các extension được phép
    private static final Set<String> ALLOWED_EXTENSIONS = new HashSet<>(
            Arrays.asList("jpg", "jpeg", "png", "gif", "webp")
    );

    @GetMapping("/images/{fileName}")
    public ResponseEntity<Resource> getImage(@PathVariable String fileName) {
        // 1. Validate fileName không được null hoặc empty
        if (!StringUtils.hasText(fileName)) {
            return ResponseEntity.badRequest().build();
        }

        // 2. Validate file extension
        String extension = getFileExtension(fileName);
//        if (!ALLOWED_EXTENSIONS.contains(extension.toLowerCase())) {
//            return ResponseEntity.badRequest().build();
//        }

        // 3. Normalize và validate đường dẫn
        Path normalizedPath = Paths.get(UPLOAD_DIR, fileName).normalize();
        Path uploadDirPath = Paths.get(UPLOAD_DIR).normalize();

        // 4. Kiểm tra path traversal
        if (!normalizedPath.startsWith(uploadDirPath)) {
            return ResponseEntity.badRequest().build();
        }

        File file = normalizedPath.toFile();

        // 5. Kiểm tra file tồn tại
        if (!file.exists() || !file.isFile()) {
            return ResponseEntity.notFound().build();
        }

        Resource resource = new FileSystemResource(file);

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "inline; filename=" + fileName)
                .body(resource);
    }

    private String getFileExtension(String fileName) {
        int lastDotIndex = fileName.lastIndexOf('.');
        return lastDotIndex > 0 ? fileName.substring(lastDotIndex + 1) : "";
    }
}