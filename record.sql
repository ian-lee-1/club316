-- create the new table called trades to keep track of trade
CREATE TABLE record (
    id INTEGER NOT NULL,
    transaction_id INTEGER PRIMARY KEY AUTOINCREMENT,
    symbol TEXT NOT NULL,
    shares INTEGER NOT NULL,
    price NUMERIC NOT NULL,
    method TEXT NOT NULL,
    transacted TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(id) REFERENCES users(id)
);

