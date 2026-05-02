// FIXED BUGS & UI IMPROVEMENTS:
// - Added tab management with 'tab-active' classes.
// - Implemented 'noDevicesPlaceholder' visibility logic.
// - Added 'clearAlerts' functionality.
// - Improved sidebar 'open' state management.
// - Added auto-refresh for Stats in Intelligence Hub.

document.addEventListener('DOMContentLoaded', () => {
    // UI Elements
    const elements = {
        scanBtn: document.getElementById('scanBtn'),
        subnetInput: document.getElementById('subnetInput'),
        interfaceSelect: document.getElementById('interfaceSelect'),
        speedSelect: document.getElementById('speedSelect'),
        passiveMode: document.getElementById('passiveMode'),
        deviceTableBody: document.getElementById('deviceTableBody'),
        noDevicesPlaceholder: document.getElementById('noDevicesPlaceholder'),
        networkScore: document.getElementById('networkScore'),
        progressContainer: document.getElementById('progressContainer'),
        progressBar: document.getElementById('progressBar'),
        progressPercent: document.getElementById('progressPercent'),
        currentAction: document.getElementById('currentAction'),
        errorBanner: document.getElementById('errorBanner'),
        errorMessage: document.getElementById('errorMessage'),
        liveBadge: document.getElementById('liveBadge'),
        // Views & Tabs
        showRecon: document.getElementById('showRecon'),
        showSecurity: document.getElementById('showSecurity'),
        showHistory: document.getElementById('showHistory'),
        showSettings: document.getElementById('showSettings'),
        reconView: document.getElementById('reconView'),
        securityView: document.getElementById('securityView'),
        historyView: document.getElementById('historyView'),
        settingsView: document.getElementById('settingsView'),
        historyTableBody: document.getElementById('historyTableBody'),
        // Intelligence Hub
        alertsContainer: document.getElementById('alertsContainer'),
        clearAlerts: document.getElementById('clearAlerts'),
        statDevices: document.getElementById('statDevices'),
        statCritical: document.getElementById('statCritical'),
        statRisk: document.getElementById('statRisk'),
        // Sidebar & UI
        detailCard: document.getElementById('detailCard'),
        detailPlaceholder: document.getElementById('detailPlaceholder'),
        deviceContent: document.getElementById('deviceContent'),
        exportCsvBtn: document.getElementById('exportCsvBtn'),
        exportJsonBtn: document.getElementById('exportJsonBtn'),
        // Settings
        settingsForm: document.getElementById('settingsForm'),
        // Alert Pagination & Filtering
        alertSeverityFilter: document.getElementById('alertSeverityFilter'),
        alertPageInfo: document.getElementById('alertPageInfo'),
        prevAlerts: document.getElementById('prevAlerts'),
        nextAlerts: document.getElementById('nextAlerts'),
        // History Pagination & Filtering
        historyIpFilter: document.getElementById('historyIpFilter'),
        historyDateStart: document.getElementById('historyDateStart'),
        historyDateEnd: document.getElementById('historyDateEnd'),
        historyPageInfo: document.getElementById('historyPageInfo'),
        prevHistory: document.getElementById('prevHistory'),
        nextHistory: document.getElementById('nextHistory')
    };

    let cy = null;
    let lastScanData = [];
    let currentSocket = null;
    let isScanning = false;

    // Pagination State
    let alertPage = 1;
    let historyPage = 1;
    const itemsPerPage = 50;

    // --- Tab Management ---
    const switchTab = (activeBtn, viewId) => {
        [elements.showRecon, elements.showSecurity, elements.showHistory, elements.showSettings].forEach(btn => btn.classList.remove('tab-active'));
        [elements.reconView, elements.securityView, elements.historyView, elements.settingsView].forEach(view => view.classList.add('hidden'));
        
        activeBtn.classList.add('tab-active');
        document.getElementById(viewId).classList.remove('hidden');
        if (viewId === 'topology') cy.resize();
    };

    elements.showRecon.onclick = () => switchTab(elements.showRecon, 'reconView');
    elements.showSecurity.onclick = () => { switchTab(elements.showSecurity, 'securityView'); fetchAlerts(); };
    elements.showHistory.onclick = () => { switchTab(elements.showHistory, 'historyView'); fetchHistory(); };
    elements.showSettings.onclick = () => { switchTab(elements.showSettings, 'settingsView'); fetchSettings(); };

    // --- SSE Monitoring Listener ---
    const startSSEListener = () => {
        const sse = new EventSource(`/api/events`);
        sse.onopen = () => elements.liveBadge.classList.remove('hidden');
        sse.onmessage = (e) => {
            const alert = JSON.parse(e.data);
            renderAlert(alert);
        };
        sse.onerror = () => {
            elements.liveBadge.classList.add('hidden');
            sse.close();
            setTimeout(startSSEListener, 10000);
        };
    };
    startSSEListener();

    // --- Interface & Initialization ---
    const init = async () => {
        try {
            // Load Interfaces
            const resp = await fetch('/api/interfaces');
            const result = await resp.json();
            if (result.status === 'success') {
                elements.interfaceSelect.innerHTML = '<option value="">Auto-Detect</option>' + 
                    result.data.map(i => `<option value="${i.name}" data-cidr="${i.cidr}">${i.name} (${i.ip})</option>`).join('');
            }

            // Load and Apply Settings
            const settingsResp = await fetch('/api/settings');
            const settingsResult = await settingsResp.json();
            if (settingsResult.status === 'success') {
                const s = settingsResult.data;
                elements.speedSelect.value = s.scan_speed;
                if (s.auto_scan === 'true') {
                    console.log("Auto-scan enabled, starting...");
                    setTimeout(startScan, 1000);
                }
            }
        } catch (e) { console.error("Init error:", e); }
    };
    init();

    elements.interfaceSelect.onchange = () => {
        const sel = elements.interfaceSelect.options[elements.interfaceSelect.selectedIndex];
        if (sel.dataset.cidr) elements.subnetInput.value = sel.dataset.cidr;
    };

    // --- Cytoscape Init ---
    const initCy = () => {
        cy = cytoscape({
            container: document.getElementById('topology'),
            style: [
                { selector: 'node', style: { 
                    'background-color': '#1e293b', 
                    'label': 'data(id)', 
                    'color': '#94a3b8', 
                    'font-size': '8px', 
                    'text-valign': 'bottom', 
                    'width': 35, 
                    'height': 35, 
                    'border-width': 2, 
                    'border-color': '#334155', 
                    'text-margin-y': '5px',
                    'transition-property': 'background-color, border-color, width, height',
                    'transition-duration': '0.3s'
                } },
                { selector: 'edge', style: { 
                    'width': 1.5, 
                    'line-color': 'rgba(59, 130, 246, 0.2)', 
                    'curve-style': 'haystack', 
                    'line-style': 'solid'
                } },
                { selector: '.gateway', style: { 
                    'background-color': '#2563eb', 
                    'width': 50, 
                    'height': 50, 
                    'border-color': '#60a5fa', 
                    'border-width': 3,
                    'shadow-blur': '15px', 
                    'shadow-color': '#3b82f6',
                    'shadow-opacity': 0.5
                } },
                { selector: '.high-risk', style: { 
                    'border-color': '#ef4444', 
                    'border-width': 3,
                    'background-color': '#450a0a'
                } }
            ],
            layout: { 
                name: 'concentric',
                padding: 50,
                animate: true,
                concentric: function(node) { return node.hasClass('gateway') ? 2 : 1; },
                levelWidth: function() { return 1; }
            }
        });
        cy.on('tap', 'node', (e) => renderDetails(e.target.data('device')));
    };
    initCy();

    const renderAlert = (alert, append = false) => {
        const div = document.createElement('div');
        const sevClass = `badge-${alert.sev.toLowerCase()}`;
        div.className = `p-4 rounded-xl glass border border-white/5 transition-all animate-slide-in`;
        div.innerHTML = `
            <div class="flex justify-between items-start mb-1">
                <span class="badge ${sevClass}">${alert.type}</span>
                <span class="text-[8px] text-slate-500 font-mono">${new Date(alert.timestamp).toLocaleTimeString()}</span>
            </div>
            <p class="text-xs text-white font-medium">${alert.msg}</p>
            <p class="text-[9px] text-slate-500 mt-1 font-mono">${alert.ip || 'Global'}</p>
        `;
        if (append) elements.alertsContainer.appendChild(div);
        else elements.alertsContainer.prepend(div);
    };

    const fetchAlerts = async (page = 1) => {
        alertPage = page;
        const sev = elements.alertSeverityFilter.value;
        const resp = await fetch(`/api/alerts?page=${alertPage}&limit=${itemsPerPage}${sev ? `&severity=${sev}` : ''}`);
        const result = await resp.json();
        if (result.status === 'success') {
            elements.alertsContainer.innerHTML = '';
            result.data.forEach(a => renderAlert(a, true));
            
            elements.alertPageInfo.textContent = `Page ${alertPage}`;
            elements.prevAlerts.disabled = alertPage <= 1;
            elements.nextAlerts.disabled = result.data.length < itemsPerPage;
        }
    };

    elements.alertSeverityFilter.onchange = () => fetchAlerts(1);
    elements.prevAlerts.onclick = () => fetchAlerts(alertPage - 1);
    elements.nextAlerts.onclick = () => fetchAlerts(alertPage + 1);

    elements.clearAlerts.onclick = () => { elements.alertsContainer.innerHTML = ''; };

    // --- Core Scan Engine ---
    const startScan = () => {
        const subnet = elements.subnetInput.value.trim();
        const iface = elements.interfaceSelect.value;
        const speed = elements.speedSelect.value;
        const passive = elements.passiveMode.checked;
        
        isScanning = true;
        if (cy) { cy.elements().remove(); cy.resize(); }
        document.getElementById('topology').classList.add('scanning');
        elements.scanBtn.textContent = "Stop Scan";
        elements.scanBtn.classList.replace('bg-blue-600', 'bg-red-600');
        elements.progressContainer.classList.remove('hidden');
        elements.deviceTableBody.innerHTML = ''; 
        elements.noDevicesPlaceholder.classList.add('hidden');
        lastScanData = []; 
        
        currentSocket = new WebSocket(`${window.location.protocol === 'https:' ? 'wss:' : 'ws:'}//${window.location.host}/ws/scan`);
        currentSocket.onopen = () => {
            currentSocket.send(JSON.stringify({ subnet, interface: iface, speed, passive }));
        };

        currentSocket.onmessage = (e) => {
            const msg = JSON.parse(e.data);
            if (msg.type === 'status') {
                elements.currentAction.textContent = msg.state;
                elements.progressBar.style.width = `${msg.progress}%`;
                elements.progressPercent.textContent = `${msg.progress}%`;
                if (msg.state === 'Completed') {
                    resetUI();
                    cy.layout({ name: 'concentric', animate: true, padding: 60 }).run();
                    setTimeout(() => cy.fit(), 500);
                }
            } else if (msg.type === 'device') {
                updateOrAddDevice(msg.data);
            } else if (msg.type === 'security_report') {
                msg.alerts.forEach(renderAlert);
                updateSecurityStats(msg);
            } else if (msg.type === 'error') {
                elements.errorBanner.classList.remove('hidden');
                elements.errorMessage.textContent = msg.message;
                resetUI();
            }
        };
        currentSocket.onclose = () => resetUI();
    };

    const updateOrAddDevice = (device) => {
        const existingIdx = lastScanData.findIndex(d => d.ip === device.ip);
        if (existingIdx !== -1) {
            lastScanData[existingIdx] = { ...lastScanData[existingIdx], ...device };
            const row = document.getElementById(`device-row-${device.ip.replace(/\./g, '-')}`);
            if (row) row.querySelector('.packet-count').textContent = device.packets || 1;
        } else {
            lastScanData.push(device);
            renderDeviceRow(device);
            addNodeToTopology(device);
            // Run a quick layout for the first few devices
            if (lastScanData.length < 5) {
                cy.layout({ name: 'concentric', animate: true, padding: 30 }).run();
            }
        }
        elements.noDevicesPlaceholder.classList.add('hidden');
    };

    const resetUI = () => {
        isScanning = false;
        document.getElementById('topology').classList.remove('scanning');
        elements.scanBtn.textContent = "Start Intel Scan";
        elements.scanBtn.classList.replace('bg-red-600', 'bg-blue-600');
        elements.progressContainer.classList.add('hidden');
        if (lastScanData.length === 0) elements.noDevicesPlaceholder.classList.remove('hidden');
        currentSocket = null;
    };

    elements.scanBtn.onclick = () => isScanning ? (currentSocket.close(), resetUI()) : startScan();

    const renderDeviceRow = (d) => {
        const tr = document.createElement('tr'); 
        tr.id = `device-row-${d.ip.replace(/\./g, '-')}`;
        tr.className = 'border-b border-white/5 hover:bg-white/5 cursor-pointer transition-colors';
        tr.innerHTML = `
            <td class="px-6 py-4"><div><span class="font-bold text-white">${d.hostname || 'Unknown'}</span><p class="text-[9px] text-slate-500 uppercase">${d.os || 'Generic IoT'}</p></div></td>
            <td class="px-6 py-4"><span class="font-mono text-blue-400 text-xs">${d.ip}</span></td>
            <td class="px-6 py-4 text-center packet-count font-bold text-slate-300 font-mono">${d.packets || 1}</td>
            <td class="px-6 py-4 text-center"><span class="px-2 py-1 rounded bg-blue-500/10 text-blue-400 text-[9px] font-bold uppercase tracking-tighter">${d.method}</span></td>
            <td class="px-6 py-4 text-center"><span class="px-3 py-1 rounded-full bg-white/5 border border-white/10 ${d.risk_score > 0 ? 'text-red-400' : 'text-green-400'} text-[10px] font-bold">${d.risk_score > 0 ? `${d.vulnerabilities.length} CVEs` : 'Secure'}</span></td>
        `;
        tr.onclick = () => renderDetails(d);
        elements.deviceTableBody.appendChild(tr);
    };

    const addNodeToTopology = (d) => {
        const isGW = d.ip.endsWith('.1') || (d.hostname && d.hostname.toLowerCase().includes('router'));
        cy.add({ group: 'nodes', data: { id: d.ip, device: d }, classes: (isGW ? 'gateway ' : '') + (d.risk_score > 0 ? 'high-risk' : '') });
        if (!isGW) { const gw = cy.nodes('.gateway').first(); if (gw.length) cy.add({ group: 'edges', data: { source: gw.id(), target: d.ip } }); }
    };

    const updateSecurityStats = (data) => {
        elements.statDevices.textContent = lastScanData.length;
        elements.networkScore.textContent = data.score;
        elements.statRisk.textContent = lastScanData.reduce((acc, d) => acc + (d.risk_score || 0), 0);
        elements.statCritical.textContent = lastScanData.reduce((acc, d) => acc + (d.vulnerabilities || []).filter(v => v.severity === 'Critical').length, 0);
    };

    const fetchHistory = async (page = 1) => {
        historyPage = page;
        const ip = elements.historyIpFilter.value;
        const start = elements.historyDateStart.value;
        const end = elements.historyDateEnd.value;
        
        let url = `/api/history?page=${historyPage}&limit=${itemsPerPage}`;
        if (ip) url += `&ip=${encodeURIComponent(ip)}`;
        if (start) url += `&start_date=${start}`;
        if (end) url += `&end_date=${end}`;

        const resp = await fetch(url);
        const result = await resp.json();
        if (result.status === 'success') {
            elements.historyTableBody.innerHTML = result.data.map(d => `
                <tr class="border-b border-white/5 hover:bg-white/5 cursor-pointer">
                    <td class="px-6 py-4 text-xs text-slate-400">${d.scan_time}</td>
                    <td class="px-6 py-4 font-mono text-blue-400 text-xs">${d.ip}</td>
                    <td class="px-6 py-4 text-white font-bold">${d.hostname || 'Unknown'}</td>
                    <td class="px-6 py-4 uppercase text-[9px] text-slate-500">${d.os || 'Unknown'}</td>
                    <td class="px-6 py-4 text-center font-bold text-red-400">${d.risk_score}</td>
                    <td class="px-6 py-4 text-center"><span class="px-2 py-1 rounded bg-white/5 border border-white/10 text-[10px]">${d.vulnerabilities ? d.vulnerabilities.length : 0}</span></td>
                </tr>
            `).join('');

            const totalPages = Math.ceil(result.total / itemsPerPage);
            elements.historyPageInfo.textContent = `Page ${historyPage} of ${totalPages || 1} (${result.total} Total)`;
            elements.prevHistory.disabled = historyPage <= 1;
            elements.nextHistory.disabled = historyPage >= totalPages;
        }
    };

    // Filter Listeners
    elements.historyIpFilter.oninput = () => {
        clearTimeout(elements.historyIpFilter.timer);
        elements.historyIpFilter.timer = setTimeout(() => fetchHistory(1), 500);
    };
    elements.historyDateStart.onchange = () => fetchHistory(1);
    elements.historyDateEnd.onchange = () => fetchHistory(1);
    elements.prevHistory.onclick = () => fetchHistory(historyPage - 1);
    elements.nextHistory.onclick = () => fetchHistory(historyPage + 1);

    // --- Settings Management ---
    const fetchSettings = async () => {
        try {
            const resp = await fetch('/api/settings');
            const result = await resp.json();
            if (result.status === 'success') {
                const s = result.data;
                const form = elements.settingsForm;
                form.scan_interval.value = s.scan_interval;
                form.scan_speed.value = s.scan_speed;
                form.custom_ports.value = s.custom_ports;
                form.auto_scan.checked = s.auto_scan === 'true';
                
                // Update global UI with saved settings
                elements.speedSelect.value = s.scan_speed;
            }
        } catch (e) { console.error("Error fetching settings:", e); }
    };

    elements.settingsForm.onsubmit = async (e) => {
        e.preventDefault();
        const formData = new FormData(elements.settingsForm);
        const data = {
            scan_interval: formData.get('scan_interval'),
            scan_speed: formData.get('scan_speed'),
            custom_ports: formData.get('custom_ports'),
            auto_scan: elements.settingsForm.auto_scan.checked ? 'true' : 'false'
        };

        try {
            const resp = await fetch('/api/settings', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data)
            });
            const result = await resp.json();
            if (result.status === 'success') {
                // UI feedback
                const btn = elements.settingsForm.querySelector('button[type="submit"]');
                const originalText = btn.textContent;
                btn.textContent = "Settings Saved!";
                btn.classList.replace('bg-blue-600', 'bg-green-600');
                setTimeout(() => {
                    btn.textContent = originalText;
                    btn.classList.replace('bg-green-600', 'bg-blue-600');
                }, 2000);
            }
        } catch (e) { console.error("Error saving settings:", e); }
    };

    const renderDetails = (device) => {
        if (!device) return; 
        elements.detailPlaceholder.classList.add('hidden'); 
        elements.deviceContent.classList.remove('hidden');
        elements.detailCard.classList.add('open');

        const svcs = Object.entries(device.services || {}).map(([p, info]) => `
            <div class="p-3 rounded-xl bg-white/5 border border-white/10 hover:border-blue-500/30 transition-all">
                <div class="flex justify-between text-[9px] font-bold mb-1"><span class="text-blue-400">Port ${p}</span><span>${info.name}</span></div>
                <div class="text-[10px] font-mono text-slate-400 truncate">${info.banner || 'No banner identified'}</div>
            </div>
        `).join('');

        const vulns = (device.vulnerabilities || []).map(v => `
            <div class="p-4 rounded-xl bg-red-500/5 border border-red-500/20 mb-2 group hover:bg-red-500/10 transition-all">
                <div class="flex justify-between items-center mb-1">
                    <span class="text-[10px] font-bold text-red-400">${v.cve}</span>
                    <span class="badge badge-${v.severity.toLowerCase()}">${v.severity}</span>
                </div>
                <p class="text-[10px] text-slate-300 leading-relaxed">${v.description}</p>
            </div>
        `).join('');

        elements.deviceContent.innerHTML = `
            <div class="flex items-center gap-4 mb-6 animate-slide-in">
                <div class="w-14 h-14 rounded-2xl bg-blue-500/10 flex items-center justify-center text-blue-400 text-xl font-bold border border-blue-500/20">${device.ip.split('.').pop()}</div>
                <div>
                    <h3 class="font-bold text-white text-lg">${device.hostname || 'Unknown Device'}</h3>
                    <p class="text-[10px] text-blue-400 uppercase tracking-widest font-bold">${device.os || 'Generic IoT'}</p>
                </div>
            </div>
            <div class="space-y-6 animate-slide-in" style="animation-delay: 0.1s">
                <div class="grid grid-cols-2 gap-4">
                    <div class="p-3 bg-white/5 rounded-2xl border border-white/5">
                        <p class="text-[9px] text-slate-500 font-bold uppercase mb-1">Vendor</p>
                        <p class="text-xs font-bold truncate">${device.vendor || 'Unknown'}</p>
                    </div>
                    <div class="p-3 bg-white/5 rounded-2xl border border-white/5">
                        <p class="text-[9px] text-slate-500 font-bold uppercase mb-1">Risk Pts</p>
                        <p class="text-xs font-bold text-red-400">${device.risk_score || 0}</p>
                    </div>
                </div>
                <div class="p-3 bg-white/5 rounded-2xl border border-white/5">
                    <p class="text-[9px] text-slate-500 font-bold uppercase mb-1">Hardware ID</p>
                    <p class="text-xs font-mono text-white">${device.mac || 'Unknown'}</p>
                </div>
                <div class="space-y-2">
                    <p class="text-[9px] text-slate-500 px-1 uppercase font-bold tracking-widest">Detected Exploits</p>
                    ${vulns || '<p class="text-[10px] italic text-slate-600 px-1">No known vulnerabilities detected.</p>'}
                </div>
                <div class="space-y-2 pb-6">
                    <p class="text-[9px] text-slate-500 px-1 uppercase font-bold tracking-widest">Active Services</p>
                    <div class="grid grid-cols-1 gap-2">${svcs || '<p class="text-[10px] italic text-slate-600 px-1">No open services found.</p>'}</div>
                </div>
            </div>
        `;
    };

    // Export Handlers
    if (elements.exportCsvBtn) {
        elements.exportCsvBtn.onclick = () => window.open('/api/export/csv', '_blank');
    }
    if (elements.exportJsonBtn) {
        elements.exportJsonBtn.onclick = () => window.open('/api/export/json', '_blank');
    }

    // Close sidebar on click outside on mobile
    window.onclick = (e) => {
        if (window.innerWidth < 1024 && !elements.detailCard.contains(e.target) && !elements.deviceTableBody.contains(e.target)) {
            elements.detailCard.classList.remove('open');
        }
    };
});
