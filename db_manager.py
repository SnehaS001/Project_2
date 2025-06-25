import sqlite3

def init_db():
    conn = sqlite3.connect("traffic.db")
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS packets (
        timestamp TEXT, src_ip TEXT, dst_ip TEXT,
        src_port TEXT, dst_port TEXT, protocol TEXT, length INTEGER
    )""")
    conn.commit()
    return conn

def log_packet(conn, pkt):
    c = conn.cursor()
    c.execute("""INSERT INTO packets VALUES (?, ?, ?, ?, ?, ?, ?)""", (
        pkt["timestamp"], pkt["src_ip"], pkt["dst_ip"],
        pkt["src_port"], pkt["dst_port"], pkt["protocol"], pkt["length"]
    ))
    conn.commit()