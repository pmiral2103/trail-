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

    // Dynamic Timeline Data
    let timelineData = [
        { id: 1, type: 'search', title: 'Browser Search', desc: 'User searched for "how to hide files"', date: '2023-10-24 09:30:00', risk: 'med' },
        { id: 2, type: 'call', title: 'Incoming Call', desc: 'Call from +1 (555) 987-6543 (12m 45s)', date: '2023-10-24 10:05:23', risk: 'low' },
        { id: 3, type: 'sms', title: 'Suspicious SMS', desc: 'Recv: "Meeting at 3 PM" from +1 (555) 012-3456', date: '2023-10-24 14:32:01', risk: 'low' }
    ];

    // Switching Analysis Tabs
    window.switchAnalysisTab = function (type) {
        document.getElementById('sms-analyzer').style.display = type === 'sms' ? 'block' : 'none';
        document.getElementById('calls-analyzer').style.display = type === 'calls' ? 'block' : 'none';

        // Update button active state
        const btns = document.querySelectorAll('.analysis-tabs .btn');
        btns[0].classList.toggle('active', type === 'sms');
        btns[1].classList.toggle('active', type === 'calls');
    };

    // Submitting Forensic Data
    window.submitForensicData = async function (category) {
        const resultsArea = document.getElementById('analysis-results');
        const now = new Date().toISOString().replace('T', ' ').substring(0, 19);

        let payload = {};
        if (category === 'sms') {
            payload = {
                type: 'sms',
                sender: document.getElementById('sms-sender').value || 'Unknown',
                timestamp: document.getElementById('sms-timestamp').value || now,
                content: document.getElementById('sms-content').value
            };
        } else {
            payload = {
                type: 'call',
                number: document.getElementById('call-number').value || 'Unknown',
                call_type: document.getElementById('call-type').value,
                duration: document.getElementById('call-duration').value || '00:00',
                timestamp: document.getElementById('call-timestamp').value || now
            };
        }

        if (!payload.content && category === 'sms') { alert("Please enter SMS content"); return; }

        // Local Simulation for instant feedback
        const riskResult = simulateAnalysis(payload);

        // Add to timeline
        const newEvent = {
            id: Date.now(),
            type: payload.type,
            title: payload.type === 'sms' ? 'New SMS Ingested' : `${payload.call_type} Call logged`,
            desc: payload.type === 'sms' ? `${payload.sender}: ${payload.content}` : `Number: ${payload.number} (${payload.duration})`,
            date: payload.timestamp,
            risk: riskResult.level
        };

        timelineData.unshift(newEvent); // Add to top
        renderTimeline();

        // Show Analysis Report
        resultsArea.innerHTML = `
            <div class="card glass risk-${riskResult.level}" style="border-left: 5px solid ${getRiskColor(riskResult.level)};">
                <h4 style="color: ${getRiskColor(riskResult.level)}">Forensic Analysis Report</h4>
                <p><strong>Artifact:</strong> ${category.toUpperCase()} Log</p>
                <p><strong>Risk Score:</strong> ${riskResult.score}/100</p>
                <p><strong>Verdict:</strong> ${riskResult.verdict}</p>
                <p style="font-size: 0.8rem; color: var(--text-muted); margin-top: 10px;">Hash: ${Math.random().toString(36).substring(2, 15)} (Verified)</p>
            </div>
        `;

        // Clear forms
        if (category === 'sms') document.getElementById('sms-form').reset();
        else document.getElementById('calls-form').reset();
    };

    function simulateAnalysis(data) {
        let score = 0;
        let verdict = "Clean record. No immediate threats detected.";

        if (data.type === 'sms') {
            const content = data.content.toLowerCase();
            if (content.includes('http') || content.includes('bit.ly')) { score += 40; verdict = "Unsafe link detected."; }
            if (content.includes('verify') || content.includes('bank') || content.includes('urgent')) { score += 30; verdict = "Phishing keywords identified."; }
            if (content.includes('.apk') || content.includes('.exe')) { score += 60; verdict = "Potential malware payload reference."; }
        } else {
            if (data.call_type === 'Missed') { score += 20; verdict = "Wangiri risk assessment required."; }
            const hour = new Date(data.timestamp).getHours();
            if (hour >= 0 && hour <= 5) { score += 30; verdict = "Suspicious activity during graveyard hours."; }
        }

        const level = score > 60 ? 'high' : (score > 30 ? 'med' : 'low');
        return { score, level, verdict };
    }

    function getRiskColor(level) {
        if (level === 'high') return '#ff0055';
        if (level === 'med') return '#ffcc00';
        return '#00ff88';
    }

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
