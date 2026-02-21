-- =============================================
-- Online Examination Portal - MySQL Schema
-- =============================================

-- Create database
CREATE DATABASE IF NOT EXISTS exam_portal CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE exam_portal;

-- =============================================
-- Admins table - stores admin credentials
-- =============================================
CREATE TABLE IF NOT EXISTS admins (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_username (username)
) ENGINE=InnoDB;

-- Default admin: admin / admin123 (password will be hashed by app)
-- Run: python -c "import bcrypt; print(bcrypt.hashpw(b'admin123', bcrypt.gensalt()).decode())"
-- Then INSERT the hash manually or use the app's setup

-- =============================================
-- Exams table
-- =============================================
CREATE TABLE IF NOT EXISTS exams (
    id INT AUTO_INCREMENT PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    duration_minutes INT NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_by INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (created_by) REFERENCES admins(id) ON DELETE SET NULL,
    INDEX idx_exam_password (id),
    INDEX idx_created_at (created_at)
) ENGINE=InnoDB;

-- =============================================
-- Questions table - supports MCQ, paragraph, image types
-- =============================================
CREATE TABLE IF NOT EXISTS questions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    exam_id INT NOT NULL,
    question_type ENUM('mcq', 'paragraph', 'image', 'short_answer') NOT NULL,
    question_text TEXT,
    paragraph_text TEXT COMMENT 'For paragraph typing - text to be typed',
    image_path VARCHAR(500) COMMENT 'For image question - path to uploaded image',
    correct_answer VARCHAR(500) COMMENT 'Expected answer for image/short_answer - auto-graded',
    marks INT DEFAULT 1 COMMENT 'Marks for this question',
    display_order INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (exam_id) REFERENCES exams(id) ON DELETE CASCADE,
    INDEX idx_exam_questions (exam_id),
    INDEX idx_display_order (display_order)
) ENGINE=InnoDB;

-- =============================================
-- Options table - for MCQ questions
-- =============================================
CREATE TABLE IF NOT EXISTS options (
    id INT AUTO_INCREMENT PRIMARY KEY,
    question_id INT NOT NULL,
    option_text VARCHAR(500) NOT NULL,
    is_correct TINYINT(1) DEFAULT 0,
    display_order INT DEFAULT 0,
    FOREIGN KEY (question_id) REFERENCES questions(id) ON DELETE CASCADE,
    INDEX idx_question_options (question_id)
) ENGINE=InnoDB;

-- =============================================
-- Students table - one record per student per exam attempt
-- =============================================
CREATE TABLE IF NOT EXISTS students (
    id INT AUTO_INCREMENT PRIMARY KEY,
    exam_id INT NOT NULL,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    submitted_at TIMESTAMP NULL,
    FOREIGN KEY (exam_id) REFERENCES exams(id) ON DELETE CASCADE,
    UNIQUE KEY unique_student_exam (exam_id, email),
    INDEX idx_exam_students (exam_id),
    INDEX idx_email (email)
) ENGINE=InnoDB;

-- =============================================
-- Results table - stores exam results
-- =============================================
CREATE TABLE IF NOT EXISTS results (
    id INT AUTO_INCREMENT PRIMARY KEY,
    student_id INT NOT NULL,
    exam_id INT NOT NULL,
    mcq_score INT DEFAULT 0,
    mcq_total INT DEFAULT 0,
    typing_accuracy DECIMAL(5,2) DEFAULT 0,
    total_score DECIMAL(10,2) DEFAULT 0,
    total_marks INT DEFAULT 0,
    submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (student_id) REFERENCES students(id) ON DELETE CASCADE,
    FOREIGN KEY (exam_id) REFERENCES exams(id) ON DELETE CASCADE,
    INDEX idx_exam_results (exam_id),
    INDEX idx_student_results (student_id)
) ENGINE=InnoDB;

-- =============================================
-- Student answers table - stores individual answers
-- =============================================
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
    FOREIGN KEY (option_id) REFERENCES options(id) ON DELETE SET NULL,
    INDEX idx_student_answers (student_id),
    INDEX idx_question_answers (question_id)
) ENGINE=InnoDB;
