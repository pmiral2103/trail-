// Basic interactions
document.addEventListener('DOMContentLoaded', () => {
    console.log('Mobile Forensics App Loaded');

    // Smooth Scroll for anchor links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth'
                });
            }
        });
    });

    // Timeline Data Management
    const timelineData = [
        { id: 1, type: 'search', title: 'Browser Search', desc: 'User searched for "how to hide files"', date: '2023-10-24 09:30:00', risk: 'med' },
        { id: 2, type: 'call', title: 'Incoming Call', desc: 'Call from +1 (555) 987-6543 (12m 45s)', date: '2023-10-24 10:05:23', risk: 'low' },
        { id: 3, type: 'sms', title: 'Suspicious SMS', desc: 'Recv: "Meeting at 3 PM" from +1 (555) 012-3456', date: '2023-10-24 14:32:01', risk: 'low' },
        { id: 4, type: 'sms', title: 'Outgoing SMS', desc: 'Sent: "Copy that." to +1 (555) 012-3456', date: '2023-10-24 14:35:12', risk: 'low' },
        { id: 5, type: 'alert', title: 'Malware Alert', desc: 'Suspicious APK download attempt detected', date: '2023-10-24 16:15:00', risk: 'high' },
        { id: 6, type: 'call', title: 'Missed Call', desc: 'Missed call from +1 (555) 111-2222 (Wangiri Risk)', date: '2023-10-24 18:20:11', risk: 'med' },
        { id: 7, type: 'sms', title: 'Phishing Attempt', desc: 'Recv: "Verify bank acc" from Unknown', date: '2023-10-25 09:15:00', risk: 'high' }
    ];

    const timelineFeed = document.getElementById('timeline-feed');
    const filterBtns = document.querySelectorAll('.timeline-btn');

    function renderTimeline(filter = 'all') {
        if (!timelineFeed) return;
        timelineFeed.innerHTML = '';

        let index = 0;
        timelineData.forEach(item => {
            if (filter !== 'all' && item.type !== filter) return;

            const isLeft = index % 2 === 0 ? 'left' : 'right';
            const riskClass = `risk-${item.risk}`; // risk-low, risk-med, risk-high

            const itemHTML = `
                <div class="timeline-item ${isLeft} ${riskClass}">
                    <div class="timeline-dot"></div>
                    <div class="timeline-content">
                        <span class="timeline-date">${item.date}</span>
                        <h4 class="timeline-title">${item.title}</h4>
                        <p class="timeline-desc">${item.desc}</p>
                    </div>
                </div>
            `;

            timelineFeed.innerHTML += itemHTML;
            index++;
        });
    }

    // Initial Render
    renderTimeline();

    // Filter Click Handlers
    filterBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            // Remove active class from all
            filterBtns.forEach(b => b.classList.remove('active'));
            // Add to clicked
            btn.classList.add('active');

            const filterValue = btn.getAttribute('data-filter');
            renderTimeline(filterValue);
        });
    });

    // Dashboard & Reporting Logic
    function updateDashboard() {
        const hashEl = document.getElementById('case-hash');
        const callCountEl = document.getElementById('call-count');
        const smsCountEl = document.getElementById('sms-count');

        if (hashEl) hashEl.innerText = "SHA-256: 8f92a1c7d2e4b5f6a7d8e9... (Verified)";
        if (callCountEl) callCountEl.innerText = "12";
        if (smsCountEl) smsCountEl.innerText = "5 High-Risk";
    }

    window.generateReport = function () {
        alert("Integrity Check Pulse Sent...\nScanning database blocks...\nSHA-256 Verified: 0xFD67...89AB\nAll logs match the original acquisition hash.");
        updateDashboard();
    };

    updateDashboard();

    // Secure Sandbox Logic
    window.openSandbox = function (url) {
        const modal = document.getElementById('sandbox-modal');
        const frame = document.getElementById('sandbox-frame');

        // Simulating loading a "safe" preview of a dangerous link
        frame.srcdoc = `
            <body style="font-family: sans-serif; padding: 20px; background: #f0f0f0;">
                <h2 style="color: red;">[DETECTED THREAT]</h2>
                <p>Content from <b>${url}</b> has been isolated.</p>
                <hr>
                <p>This is a sandboxed representation. Links and forms are disabled to prevent credential harvesting.</p>
                <div style="background: white; padding: 20px; border: 1px solid #ccc;">
                    <h3>Fake Login Page (Example)</h3>
                    <input type="text" placeholder="Username" disabled><br><br>
                    <input type="password" placeholder="Password" disabled><br><br>
                    <button disabled>Login</button>
                </div>
            </body>
        `;

        modal.style.display = 'flex';
        console.log(`[AUDIT] Investigator accessed suspicious content: ${url}`);
    };

    window.closeSandbox = function () {
        const modal = document.getElementById('sandbox-modal');
        modal.style.display = 'none';
    };

    // Add scroll header effect
    window.addEventListener('scroll', () => {
        const header = document.querySelector('header');
        if (window.scrollY > 50) {
            header.style.background = 'rgba(10, 10, 15, 0.95)';
        } else {
            header.style.background = 'rgba(10, 10, 15, 0.8)';
        }
    });
});
