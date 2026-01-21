# 🚨 Hướng Dẫn Build Binary `bd` An Toàn (Đã Vá Lỗ Hổng)

## Vấn Trễ
Binary `bd` hiện tại ở `/Users/thailq/.local/bin/bd` (version 0.47.1, build Jan 18)
**CHƯA có các fix bảo mật** vừa thực hiện.

## Bước 1: Cài đặt Go (nếu chưa có)

### Option A: Cài qua Homebrew (khuyến nghị)
```bash
brew install go
```

### Option B: Cài thủ công
Truy cập https://go.dev/dl/ và tải phiên bản mới nhất cho macOS.

## Bước 2: Build Binary từ Source Đã Vá Lỗi

```bash
# Di chuyển vào thư mục Beads
cd /Users/thailq/dev/beads

# Build binary (đảm bảo đang ở branch main với các commit security)
go build -o /Users/thailq/.local/bin/bd ./cmd/bd

# Kiểm tra version mới
bd --version
```

## Bước 3: Kiểm Tra Dự Án `so-quy-viet`

Dự án này đã sử dụng binary cũ. Sau khi build xong:

```bash
# Kiểm tra các issues có thể bị ảnh hưởng
cd /Users/thailq/dev/so-quy-viet

# Liệt kê các issues (kiểm tra xem có dấu hiệu injection không)
bd list

# Nếu thấy issues có nội dung lạ (như git config, file paths không mong muốn),
# hãy xem chi tiết và xóa/sửa lại
```

## Bước 4: Khởi Động Lại Daemon (Quan Trọng!)

Daemon cũ **không có bảo mật**, cần restart:

```bash
# Dừng tất cả daemon cũ
bd daemons killall

# Khởi động daemon mới (có auth, rate limiting, etc)
bd daemon start

# Kiểm tra status
bd status
```

## Các Lỗ Hổng Đã Fix và Ảnh Hưởng

### 1. Path Traversal (CRITICAL)
- **Vấn đề**: `--body-file ../etc/passwd` có thể đọc file bất kỳ
- **Ảnh hưởng**: Nếu bạn đã dùng `--body-file` với path chứa `../`, file có thể đã bị leak vào issues
- **Kiểm tra**: Tìm issues có nội dung là nội dung file hệ thống

### 2. Input Sanitization (HIGH)
- **Vấn đề**: Git config có thể inject vào issues
- **Ảnh hưởng**: Issues có thể chứa `user.email`, `user.name` từ git config
- **Kiểm tra**: `bd show` để xem các issues, nếu thấy fields lạ thì sửa

### 3. RPC Authentication (HIGH)
- **Vấn đề**: Daemon cũ không có auth, bất kỳ process nào đều có thể gọi
- **Ảnh hưởng**: Local privilege escalation nếu có malicious process
- **Fix**: Daemon mới có auth token và HMAC signing

### 4. Credential Security (HIGH)
- **Vấn đề**: Federation credentials encrypted với weak key
- **Ảnh hưởng**: Nếu attacker lấy được database file, có thể decrypt credentials
- **Fix**: Keyring với key derivation tốt hơn

### 5. Rate Limiting & Size Limits (LOW)
- **Vấn đề**: Không có protection gegen DoS
- **Fix**: 100 req/phút per client, 10MB request limit

## Sau Khi Build Xong

1. **Test cơ bản**:
```bash
cd /Users/thailq/dev/so-quy-viet
bd ready    # Kiểm tra issues sẵn sàng
bd list     # Liệt kê các issues
```

2. **Kiểm tra security**:
```bash
# Xem daemon status (đã có auth chưa)
bd status | grep -i auth

# Kiểm tra metrics
bd metrics
```

3. **Nếu mọi thứ OK**, commit lại database:
```bash
cd /Users/thailq/dev/so-quy-viet
bd sync
```

## Lưu Ý Quan Trọng

- Database SQLite lưu local, **không upload lên server**, nên lỗ hổng chủ yếu ảnh hưởng local access
- Nếu máy của bạn không bị compromise, dữ liệu có thể vẫn an toàn
- Nhưng nên **build lại ngay** để tránh các rủi ro trong tương lai

## Hỗ Trợ

Nếu gặp lỗi trong quá trình build, check:
1. Go version: `go version` (cần >= 1.21)
2. Branch hiện tại: `git branch` (nên ở main)
3. Commits security: `git log --oneline -5`
