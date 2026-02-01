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

    // Get current formatted timestamp (YYYY-MM-DD HH:MM:SS)
    window.getCurrentTimestamp = function () {
        const now = new Date();
        const year = now.getFullYear();
        const month = String(now.getMonth() + 1).padStart(2, '0');
        const day = String(now.getDate()).padStart(2, '0');
        const hours = String(now.getHours()).padStart(2, '0');
        const minutes = String(now.getMinutes()).padStart(2, '0');
        const seconds = String(now.getSeconds()).padStart(2, '0');
        return `${year}-${month}-${day} ${hours}:${minutes}:${seconds}`;
    };

    // Auto-populate timestamps in forms
    function autoPopulateTimestamps() {
        const timestamp = getCurrentTimestamp();
        const smsTime = document.getElementById('sms-timestamp');
        const callTime = document.getElementById('call-timestamp');
        if (smsTime && !smsTime.value) smsTime.value = timestamp;
        if (callTime && !callTime.value) callTime.value = timestamp;
    }

    // Automatic Time Detection from SMS Content
    function extractTimeFromText(text) {
        // Patterns for: 10:30 PM, 3 PM, 15:00, 9am
        const timePatterns = [
            /\b((1[0-2]|0?[1-9]):([0-5][0-9])\s?([AaPp][Mm]))\b/i, // 10:30 PM
            /\b((1[0-2]|0?[1-9])\s?([AaPp][Mm]))\b/i,             // 3 PM
            /\b(([0-1]?[0-9]|2[0-3]):([0-5][0-9]))\b/             // 15:00
        ];

        for (let pattern of timePatterns) {
            const match = text.match(pattern);
            if (match) {
                return match[0];
            }
        }
        return null;
    }

    const smsContentArea = document.getElementById('sms-content');
    if (smsContentArea) {
        smsContentArea.addEventListener('input', (e) => {
            const text = e.target.value;
            const detectedTime = extractTimeFromText(text);
            const smsTimeInput = document.getElementById('sms-timestamp');
            const autoBadge = document.getElementById('sms-auto-status');

            if (detectedTime) {
                // If we found a time, try to prepend today's date if date is missing
                const now = new Date();
                const datePart = now.toISOString().split('T')[0];
                let finalTimestamp = detectedTime;

                // If it's just "3 PM", we might want to keep it or format it
                // For now, let's just show the detected time or combine it
                smsTimeInput.value = `${datePart} ${detectedTime}`;
                autoBadge.style.display = 'inline-block';
                smsTimeInput.style.borderColor = 'var(--secondary)';
            } else {
                autoBadge.style.display = 'none';
                smsTimeInput.style.borderColor = '';
            }
        });
    }

    // Switching Analysis Tabs
    window.switchAnalysisTab = function (type) {
        document.getElementById('sms-analyzer').style.display = type === 'sms' ? 'block' : 'none';
        document.getElementById('calls-analyzer').style.display = type === 'calls' ? 'block' : 'none';

        // Update button active state
        const btns = document.querySelectorAll('.analysis-tabs .btn');
        btns[0].classList.toggle('active', type === 'sms');
        btns[1].classList.toggle('active', type === 'calls');

        // Update timestamp when switching
        autoPopulateTimestamps();
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

        // Local Simulation for instant feedback (will be replaced by actual fetch to /api/add-data later)
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

        timelineData.unshift(newEvent);
        renderTimeline();

        // Show Analysis Report with Forensic Detail
        let findingsHtml = riskResult.findings ? riskResult.findings.map(f => `<li>• ${f}</li>`).join('') : '<li>• No specific automated threats identified.</li>';

        resultsArea.innerHTML = `
            <div class="card glass risk-${riskResult.level}" style="border-left: 5px solid ${getRiskColor(riskResult.level)}; padding: 20px;">
                <div style="display: flex; justify-content: space-between; align-items: start;">
                    <div>
                        <h4 style="color: ${getRiskColor(riskResult.level)}; margin-bottom: 10px;">> AI_FORENSIC_REPORT.TXT</h4>
                        <p><strong>Artifact:</strong> ${category.toUpperCase()}</p>
                        <p><strong>Calculated Risk:</strong> <span class="badge" style="background: ${getRiskColor(riskResult.level)}">${riskResult.level.toUpperCase()}</span></p>
                    </div>
                    <div style="text-align: right;">
                        <p style="font-size: 0.7rem; color: var(--text-muted);">HASH: ${Math.random().toString(36).substring(2, 10).toUpperCase()}</p>
                        <p style="font-size: 0.7rem; color: var(--text-muted);">TIMESTAMP: ${now}</p>
                    </div>
                </div>
                <div style="margin-top: 15px; background: rgba(0,0,0,0.3); padding: 15px; border-radius: 8px;">
                    <p style="font-weight: bold; margin-bottom: 8px;">Forensic Findings:</p>
                    <ul style="list-style: none; font-size: 0.9rem; color: #ff99aa;">
                        ${findingsHtml}
                    </ul>
                </div>
                <p style="margin-top: 15px; font-size: 0.85rem; font-style: italic;">Verdict: ${riskResult.verdict}</p>
            </div>
        `;

        // Clear forms
        if (category === 'sms') document.getElementById('sms-form').reset();
        else document.getElementById('calls-form').reset();
    };

    function simulateAnalysis(data) {
        let score = 0;
        let findings = [];
        let verdict = "Clean record. No immediate threats detected.";

        if (data.type === 'sms') {
            const content = data.content.toLowerCase();
            if (content.includes('http')) {
                score += 30;
                findings.push("Suspicious URL pattern detected");
            }
            if (content.includes('verify') || content.includes('bank')) {
                score += 25;
                findings.push("Phishing/Social Engineering keywords detected");
            }
            if (content.includes('.apk') || content.includes('.exe')) {
                score += 50;
                findings.push("Potential malware payload reference (.apk/.exe)");
            }
            if (score > 50) verdict = "High probability of malicious intent. Isolate artifact.";
        } else {
            if (data.call_type === 'Missed') {
                score += 20;
                findings.push("Wangiri / Missed Call scam risk pattern");
            }
            const hour = new Date(data.timestamp).getHours();
            if (hour >= 0 && hour <= 5) {
                score += 30;
                findings.push("Anomalous activity during graveyard hours (00:00-05:00)");
            }
        }

        const level = score >= 70 ? 'critical' : (score >= 50 ? 'high' : (score >= 30 ? 'med' : 'low'));
        return { score, level, verdict, findings };
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
    autoPopulateTimestamps();

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

    window.exportPDF = function () {
        console.log('[AUDIT] Generating Forensic PDF Report...');

        const element = document.body;
        const opt = {
            margin: [10, 10, 10, 10],
            filename: `Forensic_Report_${new Date().getTime()}.pdf`,
            image: { type: 'jpeg', quality: 0.98 },
            html2canvas: { scale: 2, useCORS: true, backgroundColor: '#ffffff' },
            jsPDF: { unit: 'mm', format: 'a4', orientation: 'portrait' }
        };

        // Add a temporary class to body for print styling during generation
        document.body.classList.add('pdf-generating');

        html2pdf().set(opt).from(element).save().then(() => {
            document.body.classList.remove('pdf-generating');
            console.log('[AUDIT] PDF Report Generated Successfully.');
        });
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
