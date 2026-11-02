#!/bin/bash
# Chạy tự động bởi docker-entrypoint-initdb.d khi khởi tạo volume lần đầu (sau các file .sql).
# Ảnh MySQL cấp ALL cho MYSQL_USER; thu về chỉ DML: backend không cần và không được tạo/xóa bảng.
# Migration chạy bằng tài khoản quản trị (root hoặc tài khoản riêng), không dùng tài khoản của ứng dụng.
MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql -uroot <<SQL
REVOKE ALL PRIVILEGES ON \`${MYSQL_DATABASE}\`.* FROM '${MYSQL_USER}'@'%';
GRANT SELECT, INSERT, UPDATE, DELETE ON \`${MYSQL_DATABASE}\`.* TO '${MYSQL_USER}'@'%';
FLUSH PRIVILEGES;
SQL
