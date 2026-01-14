// ========================================
// SECURITY CONFIGURATION
// ========================================
const SECURITY_CONFIG = {
    SUBMIT_COOLDOWN: 60000,
    MIN_FORM_FILL_TIME: 3000,
    MAX_ATTEMPTS: 5
};

let formLoadTime = Date.now();
let suspiciousActivity = { rapidClicks: 0, lastClickTime: 0 };
const submittedMessages = new Set();

// ========================================
// ENHANCED INPUT SANITIZATION
// ========================================
function sanitizeInput(input) {
    if (!input) return '';
    
    // Use textContent for TEXT-ONLY sanitization (BEST PRACTICE)
    const div = document.createElement('div');
    div.textContent = input;
    const sanitized = div.innerHTML;
    
    // Return sanitized text with hard limit
    return sanitized.substring(0, 1000).trim();
}

// ========================================
// VALIDATION FUNCTIONS
// ========================================
function validateName(name) {
    const nameRegex = /^[ก-๙a-zA-Z\s]+$/;
    const spamWords = ['test', 'xxx', 'admin', 'spam', 'bot', 'script', 'hack'];
    const sanitized = name.toLowerCase().trim();
    
    // Check spam words
    if (spamWords.some(word => sanitized.includes(word))) {
        return false;
    }
    
    // Check excessive repetition
    if (/(.)\1{4,}/.test(sanitized)) {
        return false;
    }
    
    return nameRegex.test(name);
}

function validatePhone(phone) {
    const phoneRegex = /^0[689]\d{8}$/;
    const cleanPhone = phone.replace(/[-\s]/g, '');
    
    // Check if all digits are the same
    if (/^(\d)\1+$/.test(cleanPhone)) {
        return false;
    }
    
    return phoneRegex.test(cleanPhone);
}

function validateMessage(message) {
    const trimmed = message.trim();
    
    // Check minimum length (at least 10 characters)
    if (trimmed.length < 10) return false;
    
    // Check if message contains only spaces or special characters
    const meaningfulChars = trimmed.replace(/[\s\.\,\!\?\-\_\(\)]/g, '');
    if (meaningfulChars.length < 5) return false;
    
    // Block spam patterns
    const spamPatterns = [
        /https?:\/\//gi,  // URLs
        /\b(viagra|cialis|casino|lottery|winner|prize|congratulations|click here|free money)\b/gi,
        /(.)\1{10,}/  // Excessive repetition
    ];
    
    return !spamPatterns.some(pattern => pattern.test(message));
}

// ========================================
// BOT DETECTION
// ========================================
function detectBot() {
    const form = document.getElementById('contactForm');
    
    // Check honeypot fields
    if (form.website.value !== '' || 
        form.business_email.value !== '' || 
        form.company_name.value !== '') {
        return true;
    }
    
    // Check form fill time
    const fillTime = Date.now() - formLoadTime;
    if (fillTime < SECURITY_CONFIG.MIN_FORM_FILL_TIME) {
        return true;
    }
    
    // Check suspicious rapid clicks
    if (suspiciousActivity.rapidClicks > 10) {
        return true;
    }
    
    return false;
}

// ========================================
// MESSAGE DEDUPLICATION (แก้ไขให้รองรับภาษาไทย)
// ========================================
function checkDuplicateMessage(message) {
    // ใช้ TextEncoder เพื่อรองรับภาษาไทยและอักขระพิเศษ
    const encoder = new TextEncoder();
    const data = encoder.encode(message.toLowerCase().trim());
    
    // สร้าง hash แบบง่าย
    let hash = 0;
    for (let i = 0; i < data.length; i++) {
        hash = ((hash << 5) - hash) + data[i];
        hash = hash & hash; // Convert to 32bit integer
    }
    const messageHash = hash.toString();
    
    if (submittedMessages.has(messageHash)) {
        return true;
    }
    
    submittedMessages.add(messageHash);
    return false;
}

// ========================================
// PHONE NUMBER PROTECTION
// ========================================
function initPhoneReveal() {
    const phoneDisplay = document.getElementById('phoneDisplay');
    
    if (!phoneDisplay) return;
    
    phoneDisplay.style.cursor = 'pointer';
    phoneDisplay.addEventListener('click', function() {
        const now = Date.now();
        
        // Detect rapid clicking (bot behavior)
        if (now - suspiciousActivity.lastClickTime < 500) {
            suspiciousActivity.rapidClicks++;
            if (suspiciousActivity.rapidClicks > 3) {
                return; // Block suspicious activity
            }
        } else {
            suspiciousActivity.rapidClicks = 0;
        }
        
        suspiciousActivity.lastClickTime = now;
        
        // Reveal obfuscated phone numbers
        const p1 = ['0','9','7','-','6','9','3','-','5','4','6','5'];
        const p2 = ['0','9','3','-','6','9','4','-','2','4','5','6'];
        this.textContent = p1.join('') + ', ' + p2.join('');
        this.style.cursor = 'default';
    }, { once: true });
}

// ========================================
// MOBILE MENU
// ========================================
function toggleMenu() {
    const nav = document.getElementById('navLinks');
    nav.classList.toggle('active');
}

function initMobileMenu() {
    document.querySelectorAll('.nav-links a').forEach(link => {
        link.addEventListener('click', () => {
            document.getElementById('navLinks').classList.remove('active');
        });
    });
}

// ========================================
// FORM SUBMISSION
// ========================================
async function handleFormSubmit(event) { // เพิ่ม async ข้างหน้าฟังก์ชัน
    event.preventDefault();
    
    const submitBtn = document.getElementById('submitBtn');
    const alertSuccess = document.getElementById('alertSuccess');
    const alertError = document.getElementById('alertError');
    const alertWarning = document.getElementById('alertWarning');
    const form = event.target;
    
    // 1. ดึงค่า Token จากการติ๊ก reCAPTCHA (ส่วนที่เพิ่มใหม่)
    const recaptchaResponse = grecaptcha.getResponse();
    if (!recaptchaResponse) {
        alertError.textContent = '❌ กรุณาติ๊กยืนยันว่าคุณไม่ใช่โปรแกรมอัตโนมัติ';
        alertError.classList.add('show');
        return false;
    }
    
    // ปิด Alert เดิม
    [alertSuccess, alertError, alertWarning].forEach(el => el.classList.remove('show'));
    
    // 2. SECURITY CHECK เดิมของคุณ (Honeypot, Time check)
    if (detectBot()) {
        grecaptcha.reset(); // รีเซ็ตแคปช่าถ้าตรวจพบว่าเป็นบอท
        return false; 
    }
    
    // 3. ตรวจสอบ Rate Limiting (เดิมของคุณ)
    const now = Date.now();
    const lastSubmit = localStorage.getItem('kp_last_submit');
    const attemptCount = parseInt(localStorage.getItem('kp_attempt_count') || '0');
    
    if (attemptCount >= SECURITY_CONFIG.MAX_ATTEMPTS) {
        alertError.textContent = '❌ คุณส่งข้อความครบจำนวนแล้ว กรุณาติดต่อทางโทรศัพท์';
        alertError.classList.add('show');
        grecaptcha.reset();
        return false;
    }

    // 4. เตรียมข้อมูลและ Validation (เดิมของคุณ)
    const name = sanitizeInput(form.from_name.value);
    const phone = sanitizeInput(form.phone.value);
    const service = sanitizeInput(form.service.value);
    const message = sanitizeInput(form.message.value);
    
    if (!validateName(name) || !validatePhone(phone) || !validateMessage(message) || !service) {
        alertError.textContent = '❌ กรุณากรอกข้อมูลให้ถูกต้องตามที่กำหนด';
        alertError.classList.add('show');
        grecaptcha.reset(); // ต้องรีเซ็ตเพื่อให้ติ๊กใหม่ได้
        return false;
    }

    // 5. ส่งข้อมูลไปยัง EmailJS
    submitBtn.disabled = true;
    submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> กำลังส่ง...';
    
    const templateParams = {
        from_name: name,
        phone: phone,
        service: service,
        message: message,
        'g-recaptcha-response': recaptchaResponse, // *** สำคัญ: ส่ง Token ไปให้ EmailJS ตรวจสอบ ***
        timestamp: new Date().toLocaleString('th-TH')
    };
    
    emailjs.send('service_liwyg8j', 'template_qfqgy9o', templateParams)
        .then(function(response) {
            alertSuccess.classList.add('show');
            form.reset();
            grecaptcha.reset(); // รีเซ็ตตัวติ๊กถูกหลังส่งสำเร็จ
            submitBtn.disabled = false;
            submitBtn.innerHTML = '<i class="fas fa-paper-plane"></i> ส่งข้อความ';
            localStorage.setItem('kp_last_submit', Date.now().toString());
            localStorage.setItem('kp_attempt_count', (attemptCount + 1).toString());
        })
        .catch(function(error) {
            alertError.textContent = '❌ เกิดข้อผิดพลาด กรุณาลองใหม่';
            alertError.classList.add('show');
            grecaptcha.reset(); // รีเซ็ตตัวติ๊กถูกเพื่อให้ลองใหม่ได้
            submitBtn.disabled = false;
            submitBtn.innerHTML = '<i class="fas fa-paper-plane"></i> ส่งข้อความ';
        });
}

// ========================================
// FORM HISTORY PROTECTION
// ========================================
function initFormProtection() {
    if (window.history.replaceState) {
        window.history.replaceState(null, null, window.location.href);
    }
    
    window.addEventListener('beforeunload', function() {
        const form = document.getElementById('contactForm');
        if (form) form.reset();
    });
}

// ========================================
// PRODUCTION MODE
// ========================================
function disableConsoleInProduction() {
    if (window.location.hostname !== 'localhost' && 
        window.location.hostname !== '127.0.0.1') {
        console.log = console.warn = console.error = console.info = function() {};
    }
}

// ========================================
// INITIALIZATION
// ========================================
document.addEventListener('DOMContentLoaded', function() {
    // Initialize form load time
    formLoadTime = Date.now();
    
    // Initialize EmailJS
    emailjs.init("HBnjcsrLCtxKOiSBP");
    
    // Initialize phone reveal
    initPhoneReveal();
    
    // Initialize mobile menu
    initMobileMenu();
    
    // Initialize form protection
    initFormProtection();
    
    // Disable console in production
    disableConsoleInProduction();
    
    // Attach form submit handler
    const contactForm = document.getElementById('contactForm');
    if (contactForm) {
        contactForm.addEventListener('submit', handleFormSubmit);
    }
});

// ========================================
// MOBILE MENU (UPDATED)
// ========================================
function toggleMenu() {
    const nav = document.getElementById('navLinks');
    nav.classList.toggle('active');
}

function initMobileMenu() {
    // 1. จัดการปุ่มเมนู (Hamburger Icon)
    const menuBtn = document.querySelector('.mobile-menu-btn');
    if (menuBtn) {
        menuBtn.addEventListener('click', toggleMenu);
    }

    // 2. จัดการลิ้งก์ (เมื่อกดแล้วให้ปิดเมนู)
    document.querySelectorAll('.nav-links a').forEach(link => {
        link.addEventListener('click', () => {
            const nav = document.getElementById('navLinks');
            // ลบคลาส active ออก เพื่อปิดเมนู
            nav.classList.remove('active');
        });
    });
}