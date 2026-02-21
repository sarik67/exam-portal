"""
Initialize the exam_portal database - creates database and all tables.
Run this once before using the app.
"""

import pymysql
import config

# Connect without specifying database (to create it)
conn = pymysql.connect(
    host=config.DB_CONFIG['host'],
    user=config.DB_CONFIG['user'],
    password=config.DB_CONFIG['password'],
    charset='utf8mb4'
)

with conn.cursor() as cur:
    # Create database
    cur.execute("CREATE DATABASE IF NOT EXISTS exam_portal CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")
    cur.execute("USE exam_portal")
    
    # Create tables
    cur.execute("""
        CREATE TABLE IF NOT EXISTS admins (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(100) NOT NULL UNIQUE,
            password_hash VARCHAR(255) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_username (username)
        ) ENGINE=InnoDB
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS exams (
            id INT AUTO_INCREMENT PRIMARY KEY,
            title VARCHAR(255) NOT NULL,
            duration_minutes INT NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            created_by INT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_created_at (created_at)
        ) ENGINE=InnoDB
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS questions (
            id INT AUTO_INCREMENT PRIMARY KEY,
            exam_id INT NOT NULL,
            question_type ENUM('mcq', 'paragraph', 'image', 'short_answer') NOT NULL,
            question_text TEXT,
            paragraph_text TEXT,
            image_path VARCHAR(500),
            correct_answer VARCHAR(500),
            marks INT DEFAULT 1,
            display_order INT DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (exam_id) REFERENCES exams(id) ON DELETE CASCADE,
            INDEX idx_exam_questions (exam_id)
        ) ENGINE=InnoDB
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS options (
            id INT AUTO_INCREMENT PRIMARY KEY,
            question_id INT NOT NULL,
            option_text VARCHAR(500) NOT NULL,
            is_correct TINYINT(1) DEFAULT 0,
            display_order INT DEFAULT 0,
            FOREIGN KEY (question_id) REFERENCES questions(id) ON DELETE CASCADE,
            INDEX idx_question_options (question_id)
        ) ENGINE=InnoDB
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS students (
            id INT AUTO_INCREMENT PRIMARY KEY,
            exam_id INT NOT NULL,
            name VARCHAR(255) NOT NULL,
            email VARCHAR(255) NOT NULL,
            started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            submitted_at TIMESTAMP NULL,
            FOREIGN KEY (exam_id) REFERENCES exams(id) ON DELETE CASCADE,
            UNIQUE KEY unique_student_exam (exam_id, email),
            INDEX idx_exam_students (exam_id)
        ) ENGINE=InnoDB
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS results (
            id INT AUTO_INCREMENT PRIMARY KEY,
            student_id INT NOT NULL,
            exam_id INT NOT NULL,
            mcq_score INT DEFAULT 0,
            mcq_total INT DEFAULT 0,
            typing_accuracy DECIMAL(5,2) DEFAULT 0,
            total_score DECIMAL(10,2) DEFAULT 0,
            total_marks DECIMAL(10,2) DEFAULT 0,
            submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (student_id) REFERENCES students(id) ON DELETE CASCADE,
            FOREIGN KEY (exam_id) REFERENCES exams(id) ON DELETE CASCADE,
            INDEX idx_exam_results (exam_id)
        ) ENGINE=InnoDB
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS student_answers (
            id INT AUTO_INCREMENT PRIMARY KEY,
            student_id INT NOT NULL,
            question_id INT NOT NULL,
            answer_text TEXT,
            option_id INT NULL,
            is_correct TINYINT(1) NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (student_id) REFERENCES students(id) ON DELETE CASCADE,
            FOREIGN KEY (question_id) REFERENCES questions(id) ON DELETE CASCADE,
            INDEX idx_student_answers (student_id)
        ) ENGINE=InnoDB
    """)
    conn.commit()
    print("Database 'exam_portal' and tables created successfully!")
conn.close()
