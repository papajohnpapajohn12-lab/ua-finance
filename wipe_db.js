const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('./finance.db');

db.serialize(() => {
    console.log("Wiping database...");
    db.run("DELETE FROM transactions");
    db.run("DELETE FROM categories");
    db.run("DELETE FROM stashes");
    db.run("DELETE FROM users"); // This will cascade delete if foreign keys enforced, but manual delete is safer
    console.log("Database cleared.");
});
