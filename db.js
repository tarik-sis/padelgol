const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const DB_PATH = path.join(__dirname, 'padelgol.db');
const db = new sqlite3.Database(DB_PATH);

function init() {
  db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      email TEXT,
      role TEXT DEFAULT 'user',
      credit_card TEXT,
      security_question TEXT,
      security_answer TEXT,
      avatar TEXT DEFAULT '/img/default-avatar.svg',
      bio TEXT
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS courts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      sport TEXT NOT NULL,
      location TEXT,
      price REAL,
      description TEXT,
      image TEXT
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS bookings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      court_id INTEGER NOT NULL,
      slot_date TEXT NOT NULL,
      slot_time TEXT NOT NULL,
      notes TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS reviews (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      court_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      author TEXT,
      content TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      from_user TEXT,
      to_user TEXT,
      subject TEXT,
      body TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    db.get('SELECT COUNT(*) AS c FROM users', (err, row) => {
      if (err || row.c > 0) return;
      // Seed users — plaintext passwords on purpose
      const users = [
        ['admin', 'admin123', 'admin@padelgol.local', 'admin', '4111-1111-1111-1111', 'Pet name?', 'fluffy'],
        ['alice', 'password1', 'alice@example.com', 'user', '4242-4242-4242-4242', 'City?', 'madrid'],
        ['bob', 'qwerty', 'bob@example.com', 'user', '5555-5555-5555-4444', 'Mom maiden name?', 'smith'],
        ['carlos', 'letmein', 'carlos@example.com', 'user', '6011-0000-0000-0004', 'School?', 'lincoln'],
        ['vip_user', 'vip2025', 'vip@padelgol.local', 'vip', '3782-822463-10005', 'Color?', 'blue']
      ];
      const stmt = db.prepare('INSERT INTO users (username, password, email, role, credit_card, security_question, security_answer) VALUES (?, ?, ?, ?, ?, ?, ?)');
      users.forEach(u => stmt.run(u));
      stmt.finalize();

      const courts = [
        ['Center Court 1', 'paddle', 'Madrid - Chamartín', 25.0, 'Premium indoor paddle court with glass walls.', '/img/court1.svg'],
        ['Center Court 2', 'paddle', 'Madrid - Salamanca', 22.0, 'Outdoor paddle court with night lighting.', '/img/court2.svg'],
        ['Estadio Mini', 'football', 'Madrid - Vallecas', 60.0, '7-a-side football pitch, artificial turf.', '/img/court3.svg'],
        ['Campo Grande', 'football', 'Madrid - Moratalaz', 90.0, '11-a-side football pitch, natural grass.', '/img/court4.svg'],
        ['Padel Pro Arena', 'paddle', 'Barcelona - Eixample', 30.0, 'Pro-level paddle court used for tournaments.', '/img/court5.svg'],
        ['Mini Camp Nou', 'football', 'Barcelona - Gràcia', 75.0, '5-a-side covered football pitch.', '/img/court6.svg']
      ];
      const cs = db.prepare('INSERT INTO courts (name, sport, location, price, description, image) VALUES (?, ?, ?, ?, ?, ?)');
      courts.forEach(c => cs.run(c));
      cs.finalize();

      const bookings = [
        [1, 1, '2026-05-12', '18:00', 'Admin reserved slot — internal'],
        [2, 1, '2026-05-13', '19:00', 'Match with friends'],
        [3, 3, '2026-05-14', '20:00', 'Sunday game'],
        [5, 5, '2026-05-15', '21:00', 'VIP tournament prep']
      ];
      const bs = db.prepare('INSERT INTO bookings (user_id, court_id, slot_date, slot_time, notes) VALUES (?, ?, ?, ?, ?)');
      bookings.forEach(b => bs.run(b));
      bs.finalize();

      const reviews = [
        [1, 2, 'alice', 'Great court, well maintained!'],
        [3, 3, 'bob', 'Turf could be better but fun games here.'],
        [1, 4, 'carlos', 'Loved it, will come back.']
      ];
      const rs = db.prepare('INSERT INTO reviews (court_id, user_id, author, content) VALUES (?, ?, ?, ?)');
      reviews.forEach(r => rs.run(r));
      rs.finalize();

      const messages = [
        ['admin', 'alice', 'Welcome', 'Thanks for joining PadelGol!'],
        ['admin', 'vip_user', 'Tournament', 'Your VIP slot is confirmed.']
      ];
      const ms = db.prepare('INSERT INTO messages (from_user, to_user, subject, body) VALUES (?, ?, ?, ?)');
      messages.forEach(m => ms.run(m));
      ms.finalize();

      console.log('Database seeded.');
    });
  });
}

if (require.main === module) {
  init();
}

module.exports = { db, init };
