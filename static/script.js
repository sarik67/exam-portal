/* ExamPortal — Main JS */

// Auto-dismiss flash messages after 4 seconds
document.addEventListener('DOMContentLoaded', () => {
    const flashBox = document.getElementById('flashMessages');
    if (flashBox) {
        setTimeout(() => {
            flashBox.style.transition = 'opacity 0.5s ease, transform 0.5s ease';
            flashBox.style.opacity = '0';
            flashBox.style.transform = 'translateX(20px)';
            setTimeout(() => flashBox.remove(), 500);
        }, 4000);
    }
});
