"""Áp dụng các file database/migrations/*.sql chưa có trong bảng schema_migrations, theo thứ tự tên file.

  python database/migrate.py --url "mysql+pymysql://admin:***@localhost:3306/wms"

- Dùng tài khoản có quyền DDL và EVENT (root/admin), KHÔNG dùng tài khoản của ứng dụng (chỉ có DML).
- Mỗi file tự ghi version vào schema_migrations ở cuối nên cũng nạp trực tiếp được bằng mysql client
  (docker-entrypoint-initdb.d); chạy lại runner sau đó không áp dụng lại.
- MySQL không rollback DDL: nếu một file lỗi giữa chừng, sửa tay phần đã chạy rồi chạy lại (file idempotent).
"""
import argparse
import os
import pathlib
import sys

MIGRATIONS = pathlib.Path(__file__).resolve().parent / "migrations"
BOOTSTRAP = ("CREATE TABLE IF NOT EXISTS schema_migrations ("
             "version VARCHAR(64) NOT NULL, applied_at DATETIME NOT NULL DEFAULT (UTC_TIMESTAMP()), "
             "PRIMARY KEY (version)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4")


def split_statements(sql: str) -> list[str]:
    """Tách câu lệnh theo ';', bỏ qua ';' trong chuỗi/identifier và bỏ chú thích (--, #, /* */)."""
    out, buf, quote, i, n = [], [], None, 0, len(sql)
    while i < n:
        c = sql[i]
        nxt = sql[i + 1] if i + 1 < n else ""
        if quote:
            buf.append(c)
            if c == "\\" and quote != "`" and nxt:
                buf.append(nxt)
                i += 2
                continue
            if c == quote:
                if nxt == quote:            # '' hoặc "" là ký tự thoát
                    buf.append(nxt)
                    i += 2
                    continue
                quote = None
            i += 1
            continue
        if c in ("'", '"', "`"):
            quote = c
            buf.append(c)
        elif (c == "-" and nxt == "-" and (i + 2 >= n or sql[i + 2] in " \t\r\n")) or c == "#":
            while i < n and sql[i] != "\n":
                i += 1
            continue
        elif c == "/" and nxt == "*":
            end = sql.find("*/", i + 2)
            i = n if end == -1 else end + 2
            buf.append(" ")
            continue
        elif c == ";":
            stmt = "".join(buf).strip()
            if stmt:
                out.append(stmt)
            buf = []
        else:
            buf.append(c)
        i += 1
    tail = "".join(buf).strip()
    if tail:
        out.append(tail)
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", default=os.environ.get("DATABASE_URL"), help="mặc định: biến môi trường DATABASE_URL")
    ap.add_argument("--dry-run", action="store_true", help="chỉ liệt kê file sẽ áp dụng")
    args = ap.parse_args()
    if not args.url:
        sys.exit("Thiếu --url hoặc DATABASE_URL")

    from sqlalchemy import create_engine      # import muộn để split_statements dùng được khi chưa cài thư viện
    raw = create_engine(args.url).raw_connection()     # cursor thô: không bị nội suy '%' như execute có tham số
    cur = raw.cursor()
    try:
        cur.execute("SELECT GET_LOCK('wms_migrate', 30)")
        if cur.fetchone()[0] != 1:
            sys.exit("Không lấy được khóa migrate (có tiến trình khác đang chạy?)")
        cur.execute(BOOTSTRAP)
        cur.execute("SELECT version FROM schema_migrations")
        applied = {row[0] for row in cur.fetchall()}
        pending = [f for f in sorted(MIGRATIONS.glob("*.sql")) if f.stem not in applied]
        if not pending:
            print("Schema đã mới nhất.")
            return
        for f in pending:
            print(("[dry-run] " if args.dry_run else "Áp dụng ") + f.name)
            if args.dry_run:
                continue
            for stmt in split_statements(f.read_text(encoding="utf-8")):
                cur.execute(stmt)
            cur.execute("INSERT IGNORE INTO schema_migrations (version) VALUES ('%s')" % f.stem)
        raw.commit()
    finally:
        try:
            cur.execute("SELECT RELEASE_LOCK('wms_migrate')")
        finally:
            raw.close()


if __name__ == "__main__":
    main()
