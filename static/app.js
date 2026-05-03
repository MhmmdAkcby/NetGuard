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
        showBandwidth: document.getElementById('showBandwidth'),
        wifiScanBtn: document.getElementById('wifiScanBtn'),
        reconView: document.getElementById('reconView'),
        securityView: document.getElementById('securityView'),
        historyView: document.getElementById('historyView'),
        settingsView: document.getElementById('settingsView'),
        bandwidthView: document.getElementById('bandwidthView'),
        historyTableBody: document.getElementById('historyTableBody'),
        bandwidthTableBody: document.getElementById('bandwidthTableBody'),
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
        nextHistory: document.getElementById('nextHistory'),
        timelineDate: document.getElementById('timelineDate'),
        timelineChart: document.getElementById('timelineChart')
    };

    let network = null;
    let nodes = new vis.DataSet([]);
    let edges = new vis.DataSet([]);
    let lastScanData = [];
    let currentSocket = null;
    let isScanning = false;
    let bandwidthChart = null;
    let bandwidthInterval = null;
    let blockedDevices = [];
    let timelineChart = null;

    // Pagination State
    let alertPage = 1;
    let historyPage = 1;
    const itemsPerPage = 50;

    // --- Tab Management ---
    const switchTab = (activeBtn, viewId) => {
        [elements.showRecon, elements.showSecurity, elements.showHistory, elements.showSettings, elements.showBandwidth].forEach(btn => btn.classList.remove('tab-active'));
        [elements.reconView, elements.securityView, elements.historyView, elements.settingsView, elements.bandwidthView].forEach(view => view.classList.add('hidden'));
        
        activeBtn.classList.add('tab-active');
        document.getElementById(viewId).classList.remove('hidden');
        
        // Handle Refresh intervals
        if (bandwidthInterval) { clearInterval(bandwidthInterval); bandwidthInterval = null; }
        if (viewId === 'bandwidthView') {
            initBandwidthChart();
            fetchBandwidth();
            bandwidthInterval = setInterval(fetchBandwidth, 2000);
        }

        if (viewId === 'historyView') {
            initTimelineChart();
            fetchHistoryTimeline();
        }
        
        if (viewId === 'reconView' && network) {
            setTimeout(() => {
                network.fit();
            }, 100);
        }
    };

    elements.showRecon.onclick = () => switchTab(elements.showRecon, 'reconView');
    elements.showSecurity.onclick = () => { switchTab(elements.showSecurity, 'securityView'); fetchAlerts(); };
    elements.showHistory.onclick = () => { switchTab(elements.showHistory, 'historyView'); fetchHistory(); fetchHistoryTimeline(); };
    elements.showSettings.onclick = () => { switchTab(elements.showSettings, 'settingsView'); fetchSettings(); };
    elements.showBandwidth.onclick = () => { switchTab(elements.showBandwidth, 'bandwidthView'); };

    if (elements.timelineDate) {
        elements.timelineDate.value = new Date().toISOString().split('T')[0];
        elements.timelineDate.onchange = () => fetchHistoryTimeline();
    }

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

    // --- Security Status Sync ---
    const fetchSecurityStatus = async () => {
        try {
            const resp = await fetch('/api/security/status');
            const result = await resp.json();
            if (result.status === 'success') blockedDevices = result.blocked_devices;
        } catch (e) {}
    };
    setInterval(fetchSecurityStatus, 5000);
    fetchSecurityStatus();

    elements.interfaceSelect.onchange = () => {
        const sel = elements.interfaceSelect.options[elements.interfaceSelect.selectedIndex];
        if (sel.dataset.cidr) elements.subnetInput.value = sel.dataset.cidr;
    };

    // --- vis-network Init ---
    const initNetwork = () => {
        const container = document.getElementById('topology');
        const data = { nodes, edges };
        const options = {
            nodes: {
                shape: 'dot',
                size: 25,
                font: { size: 12, color: '#94a3b8', face: 'Outfit', strokeWidth: 0 },
                borderWidth: 2,
                shadow: { enabled: true, color: 'rgba(0,0,0,0.5)', size: 10, x: 5, y: 5 }
            },
            edges: {
                width: 2,
                color: { color: 'rgba(59, 130, 246, 0.3)', highlight: '#3b82f6', hover: '#60a5fa' },
                smooth: { type: 'continuous' },
                font: { size: 9, color: '#64748b', align: 'middle', face: 'JetBrains Mono' }
            },
            physics: {
                enabled: true,
                barnesHut: { gravitationalConstant: -2000, centralGravity: 0.3, springLength: 150 },
                stabilization: { iterations: 150 }
            },
            interaction: { hover: true, tooltipDelay: 200 }
        };

        network = new vis.Network(container, data, options);

        network.on("click", (params) => {
            if (params.nodes.length > 0) {
                const nodeId = params.nodes[0];
                const nodeData = nodes.get(nodeId);
                if (nodeData && nodeData.device) renderDetails(nodeData.device);
            }
        });
    };
    initNetwork();

    // Helper for icons based on device info
    const getDeviceIcon = (d) => {
        const h = (d.hostname || '').toLowerCase();
        const os = (d.os || '').toLowerCase();
        const isWiFi = d.method === "WiFi Scan";
        
        if (isWiFi) return { shape: 'icon', icon: { face: '"Font Awesome 5 Free"', code: '\uf1eb', color: '#a855f7' } }; // Use unicode if FontAwesome is loaded, else use SVG or shapes
        
        // Using built-in shapes with colors for premium look since FA might not be here
        if (d.ip && (d.ip.endsWith('.1') || h.includes('router'))) return { color: { background: '#2563eb', border: '#60a5fa' }, size: 35 }; // Router
        if (os.includes('android') || os.includes('ios') || h.includes('phone')) return { color: { background: '#1e293b', border: '#94a3b8' } }; // Mobile
        if (os.includes('windows') || h.includes('desktop')) return { color: { background: '#1e293b', border: '#3b82f6' } }; // PC
        return { color: { background: '#0f172a', border: '#334155' } };
    };

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
    const startScan = (overrides = {}) => {
        const subnet = overrides.subnet || elements.subnetInput.value.trim();
        const iface = overrides.interface || elements.interfaceSelect.value;
        const speed = overrides.speed || elements.speedSelect.value;
        const passive = overrides.passive !== undefined ? overrides.passive : elements.passiveMode.checked;
        const surrounding = overrides.surrounding || false;
        
        isScanning = true;
        // Trigger glitch effect on start
        document.getElementById('reconView').classList.add('glitch-flash');
        setTimeout(() => document.getElementById('reconView').classList.remove('glitch-flash'), 400);
        
        if (network) { nodes.clear(); edges.clear(); }
        document.getElementById('topology').classList.add('scanning');
        
        if (surrounding) {
            elements.wifiScanBtn.textContent = "Stop WiFi Scan";
            elements.wifiScanBtn.classList.replace('bg-purple-600', 'bg-red-600');
        } else {
            elements.scanBtn.textContent = "Stop Scan";
            elements.scanBtn.classList.replace('bg-blue-600', 'bg-red-600');
        }
        
        elements.progressContainer.classList.remove('hidden');
        elements.deviceTableBody.innerHTML = ''; 
        elements.noDevicesPlaceholder.classList.add('hidden');
        lastScanData = []; 
        
        currentSocket = new WebSocket(`${window.location.protocol === 'https:' ? 'wss:' : 'ws:'}//${window.location.host}/ws/scan`);
        currentSocket.onopen = () => {
            currentSocket.send(JSON.stringify({ subnet, interface: iface, speed, passive, surrounding }));
        };

        currentSocket.onmessage = (e) => {
            const msg = JSON.parse(e.data);
            if (msg.type === 'status') {
                elements.currentAction.textContent = msg.state;
                elements.progressBar.style.width = `${msg.progress}%`;
                elements.progressPercent.textContent = `${msg.progress}%`;
                if (msg.state === 'Completed') {
                    resetUI();
                    if (network) network.fit({ animation: true });
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
        const id = (device.ip || device.bssid || '').replace(/[\.:]/g, '-');
        const existingIdx = lastScanData.findIndex(d => (d.ip || d.bssid) === (device.ip || device.bssid));
        if (existingIdx !== -1) {
            lastScanData[existingIdx] = { ...lastScanData[existingIdx], ...device };
            const row = document.getElementById(`device-row-${id}`);
            if (row) row.querySelector('.packet-count').textContent = device.packets || `CH ${device.channel}` || 1;
        } else {
            lastScanData.push(device);
            renderDeviceRow(device);
            addNodeToTopology(device);
        }
        elements.noDevicesPlaceholder.classList.add('hidden');
    };

    const resetUI = () => {
        isScanning = false;
        document.getElementById('topology').classList.remove('scanning');
        elements.scanBtn.textContent = "Start Intel Scan";
        elements.scanBtn.classList.replace('bg-red-600', 'bg-blue-600');
        elements.wifiScanBtn.textContent = "Nearby WiFi";
        elements.wifiScanBtn.classList.replace('bg-red-600', 'bg-purple-600');
        elements.progressContainer.classList.add('hidden');
        if (lastScanData.length === 0) elements.noDevicesPlaceholder.classList.remove('hidden');
        currentSocket = null;
    };

    elements.scanBtn.onclick = () => isScanning ? (currentSocket.close(), resetUI()) : startScan();
    elements.wifiScanBtn.onclick = () => isScanning ? (currentSocket.close(), resetUI()) : startScan({ surrounding: true });

    const renderDeviceRow = (d) => {
        const tr = document.createElement('tr'); 
        const isWiFi = d.method === "WiFi Scan";
        const id = (d.ip || d.bssid || '').replace(/[\.:]/g, '-');
        tr.id = `device-row-${id}`;
        tr.className = 'border-b border-white/5 hover:bg-white/5 cursor-pointer transition-colors';
        
        const name = isWiFi ? (d.ssid || 'Hidden') : (d.hostname || 'Unknown');
        const subtext = isWiFi ? (d.vendor || 'Unknown Vendor') : (d.os || 'Generic IoT');
        const address = d.ip || d.bssid || 'N/A';
        const metric = isWiFi ? `CH ${d.channel}` : (d.packets || 1);
        const method = d.method;
        
        let riskHtml = '';
        if (isWiFi) {
            const isUnsecured = (d.security || '').toLowerCase().includes('open');
            riskHtml = `<span class="px-3 py-1 rounded-full bg-white/5 border border-white/10 ${isUnsecured ? 'text-red-400' : 'text-green-400'} text-[10px] font-bold">${d.security}</span>`;
        } else {
            riskHtml = `<span class="px-3 py-1 rounded-full bg-white/5 border border-white/10 ${d.risk_score > 0 ? 'text-red-400' : 'text-green-400'} text-[10px] font-bold">${d.risk_score > 0 ? `${(d.vulnerabilities || []).length} CVEs` : 'Secure'}</span>`;
        }

        tr.innerHTML = `
            <td class="px-6 py-4"><div><span class="font-bold text-white">${name}</span><p class="text-[9px] text-slate-500 uppercase">${subtext}</p></div></td>
            <td class="px-6 py-4"><span class="font-mono text-blue-400 text-xs">${address}</span></td>
            <td class="px-6 py-4 text-center packet-count font-bold text-slate-300 font-mono">${metric}</td>
            <td class="px-6 py-4 text-center"><span class="px-2 py-1 rounded bg-blue-500/10 text-blue-400 text-[9px] font-bold uppercase tracking-tighter">${method}</span></td>
            <td class="px-6 py-4 text-center">${riskHtml}</td>
        `;
        tr.onclick = () => renderDetails(d);
        elements.deviceTableBody.appendChild(tr);
    };

    const addNodeToTopology = (d) => {
        const id = d.ip || d.bssid;
        const isGW = (d.ip && (d.ip.endsWith('.1') || (d.hostname && d.hostname.toLowerCase().includes('router'))));
        const visual = getDeviceIcon(d);
        
        const nodeData = {
            id: id,
            label: d.hostname || d.ssid || d.ip || d.bssid,
            device: d,
            ...visual,
            title: `<b>${d.hostname || d.ssid || 'Unknown'}</b><br>${d.ip || d.bssid}<br>${d.vendor || ''}`
        };

        if (d.risk_score > 0 || (d.security && d.security.toLowerCase().includes('open'))) {
            nodeData.shadow = { enabled: true, color: '#ef4444', size: 15 };
            nodeData.borderWidth = 3;
        }

        nodes.update(nodeData);

        // Linking Logic
        if (!isGW) {
            const gwNode = nodes.get({
                filter: (n) => n.device && (n.device.ip && (n.device.ip.endsWith('.1') || (n.device.hostname && n.device.hostname.toLowerCase().includes('router'))))
            })[0];

            if (gwNode) {
                // Determine "Port" label: Use first open port if available
                let edgeLabel = "";
                if (d.ports && d.ports.length > 0) {
                    edgeLabel = `Port ${d.ports[0]}`;
                } else if (d.method === "WiFi Scan") {
                    edgeLabel = `CH ${d.channel}`;
                }

                edges.update({
                    id: `e-${gwNode.id}-${id}`,
                    from: gwNode.id,
                    to: id,
                    label: edgeLabel,
                    arrows: 'to'
                });
            }
        } else {
            // If this is the gateway, link all other nodes TO it
            nodes.forEach(n => {
                if (n.id !== id) {
                    edges.update({ id: `e-${id}-${n.id}`, from: id, to: n.id, arrows: 'to' });
                }
            });
        }
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
        const isWiFi = device.method === "WiFi Scan";
        elements.detailPlaceholder.classList.add('hidden'); 
        elements.deviceContent.classList.remove('hidden');
        elements.detailCard.classList.add('open');

        let content = '';
        if (isWiFi) {
            content = `
                <div class="flex items-center gap-4 mb-6 animate-slide-in">
                    <div class="w-14 h-14 rounded-2xl bg-purple-500/10 flex items-center justify-center text-purple-400 text-xl font-bold border border-purple-500/20">
                        <svg class="w-8 h-8" fill="currentColor" viewBox="0 0 24 24"><path d="M12,21L15.6,16.2C14.6,15.45 13.35,15 12,15C10.65,15 9.4,15.45 8.4,16.2L12,21M12,3C7.95,3 4.21,4.34 1.2,6.6L3,9C5.5,7.12 8.62,6 12,6C15.38,6 18.5,7.12 21,9L22.8,6.6C19.79,4.34 16.05,3 12,3M12,9C9.3,9 6.81,9.89 4.8,11.4L6.6,13.8C8.1,12.67 9.97,12 12,12C14.03,12 15.9,12.67 17.4,13.8L19.2,11.4C17.19,9.89 14.7,9 12,9Z"/></svg>
                    </div>
                    <div>
                        <h3 class="font-bold text-white text-lg">${device.ssid || 'Hidden Network'}</h3>
                        <p class="text-[10px] text-purple-400 uppercase tracking-widest font-bold">WiFi Access Point</p>
                    </div>
                </div>
                <div class="space-y-6 animate-slide-in" style="animation-delay: 0.1s">
                    <div class="grid grid-cols-2 gap-4">
                        <div class="p-3 bg-white/5 rounded-2xl border border-white/5">
                            <p class="text-[9px] text-slate-500 font-bold uppercase mb-1">Signal</p>
                            <p class="text-xs font-bold text-purple-400">${device.signal}</p>
                        </div>
                        <div class="p-3 bg-white/5 rounded-2xl border border-white/5">
                            <p class="text-[9px] text-slate-500 font-bold uppercase mb-1">Channel</p>
                            <p class="text-xs font-bold text-white">${device.channel} (${device.band})</p>
                        </div>
                    </div>
                    <div class="p-3 bg-white/5 rounded-2xl border border-white/5">
                        <p class="text-[9px] text-slate-500 font-bold uppercase mb-1">Security</p>
                        <p class="text-xs font-bold text-white">${device.security}</p>
                    </div>
                    <div class="p-3 bg-white/5 rounded-2xl border border-white/5">
                        <p class="text-[9px] text-slate-500 font-bold uppercase mb-1">BSSID</p>
                        <p class="text-xs font-mono text-white">${device.bssid}</p>
                    </div>
                    <div class="p-3 bg-white/5 rounded-2xl border border-white/5">
                        <p class="text-[9px] text-slate-500 font-bold uppercase mb-1">Vendor</p>
                        <p class="text-xs font-bold text-white">${device.vendor}</p>
                    </div>
                </div>
            `;
        } else {
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

            content = `
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
                    
                    ${device.ip ? `
                    <div id="blockActionContainer">
                        <button id="blockBtn" class="w-full py-3 rounded-xl font-bold text-[10px] uppercase transition-all ${blockedDevices.includes(device.ip) ? 'bg-red-600/20 text-red-400 border border-red-500/30' : 'bg-white/5 text-slate-400 border border-white/10 hover:bg-white/10'}">
                            ${blockedDevices.includes(device.ip) ? 'Device Blocked - Tap to Unblock' : 'Security Action: Block Internet Access'}
                        </button>
                        <p class="text-[8px] text-slate-600 text-center mt-2 uppercase tracking-widest px-4">Disrupts connection via ARP Poisoning. Use for security mitigation only.</p>
                    </div>
                    ` : ''}

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
        }
        elements.deviceContent.innerHTML = content;
        
        // Attach block handler if IP exists
        if (device.ip) {
            const btn = document.getElementById('blockBtn');
            if (btn) {
                btn.onclick = async () => {
                    const isBlocked = blockedDevices.includes(device.ip);
                    const endpoint = isBlocked ? '/api/security/unblock' : '/api/security/block';
                    btn.textContent = "Processing...";
                    btn.disabled = true;
                    
                    try {
                        const resp = await fetch(endpoint, {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ ip: device.ip, mac: device.mac })
                        });
                        const result = await resp.json();
                        if (result.status === 'success') {
                            await fetchSecurityStatus();
                            renderDetails(device); // Re-render to update button
                        }
                    } catch (e) { console.error("Block error:", e); }
                    finally { btn.disabled = false; }
                };
            }
        }
    };

    // Export Handlers
    if (elements.exportCsvBtn) {
        elements.exportCsvBtn.onclick = () => window.open('/api/export/csv', '_blank');
    }
    if (elements.exportJsonBtn) {
        elements.exportJsonBtn.onclick = () => window.open('/api/export/json', '_blank');
    }

    const formatBytes = (bytes, decimals = 2) => {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const dm = decimals < 0 ? 0 : decimals;
        const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
    };

    const initBandwidthChart = () => {
        if (bandwidthChart) return;
        const ctx = document.getElementById('bandwidthChart').getContext('2d');
        bandwidthChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: [],
                datasets: [{
                    label: 'Transfer Rate (Kbps)',
                    data: [],
                    backgroundColor: 'rgba(59, 130, 246, 0.5)',
                    borderColor: '#3b82f6',
                    borderWidth: 1,
                    borderRadius: 8
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    y: {
                        beginAtZero: true,
                        grid: { color: 'rgba(255, 255, 255, 0.05)' },
                        ticks: { color: '#64748b', font: { size: 10 } }
                    },
                    x: {
                        grid: { display: false },
                        ticks: { color: '#64748b', font: { size: 10 } }
                    }
                }
            }
        });
    };

    const fetchBandwidth = async () => {
        try {
            const resp = await fetch('/api/bandwidth');
            const result = await resp.json();
            if (result.status === 'success') {
                const data = result.data.filter(d => d.sent > 0 || d.recv > 0).slice(0, 10);
                
                // Update Table
                elements.bandwidthTableBody.innerHTML = data.map(d => `
                    <tr class="border-b border-white/5 hover:bg-white/5">
                        <td class="px-6 py-4 font-mono text-blue-400 text-xs">${d.ip}</td>
                        <td class="px-6 py-4 text-right text-slate-400 text-xs">${formatBytes(d.sent)}</td>
                        <td class="px-6 py-4 text-right text-slate-400 text-xs">${formatBytes(d.recv)}</td>
                        <td class="px-6 py-4 text-right"><span class="px-2 py-1 rounded bg-blue-500/10 text-blue-400 text-[10px] font-bold">${d.kbps} Kbps</span></td>
                    </tr>
                `).join('');

                // Update Chart
                if (bandwidthChart) {
                    bandwidthChart.data.labels = data.map(d => d.ip);
                    bandwidthChart.data.datasets[0].data = data.map(d => d.kbps);
                    bandwidthChart.update('none'); // Update without animation for smoother real-time look
                }
            }
        } catch (e) { console.error("Error fetching bandwidth:", e); }
    };

    const initTimelineChart = () => {
        if (timelineChart) return;
        const ctx = document.getElementById('timelineChart').getContext('2d');
        timelineChart = new Chart(ctx, {
            type: 'bar',
            data: { datasets: [] },
            options: {
                indexAxis: 'y',
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: {
                        type: 'time',
                        time: { unit: 'hour', displayFormats: { hour: 'HH:mm' } },
                        grid: { color: 'rgba(255, 255, 255, 0.05)' },
                        ticks: { color: '#64748b' },
                        min: elements.timelineDate.value + 'T00:00:00',
                        max: elements.timelineDate.value + 'T23:59:59'
                    },
                    y: {
                        stacked: false,
                        grid: { display: false },
                        ticks: { color: '#64748b', font: { size: 10 } }
                    }
                },
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        callbacks: {
                            label: (ctx) => {
                                const start = new Date(ctx.raw.x[0]).toLocaleTimeString();
                                const end = new Date(ctx.raw.x[1]).toLocaleTimeString();
                                return `${ctx.dataset.label}: ${start} - ${end}`;
                            }
                        }
                    }
                }
            }
        });
    };

    const fetchHistoryTimeline = async () => {
        try {
            const date = elements.timelineDate.value;
            const resp = await fetch(`/api/history/timeline?date=${date}`);
            const result = await resp.json();
            if (result.status === 'success') {
                const groups = {};
                result.data.forEach(s => {
                    if (!groups[s.label]) groups[s.label] = [];
                    groups[s.label].push({ x: [s.start, s.end], y: s.label });
                });

                timelineChart.options.scales.x.min = date + 'T00:00:00';
                timelineChart.options.scales.x.max = date + 'T23:59:59';
                
                timelineChart.data.datasets = Object.entries(groups).map(([label, data], i) => ({
                    label: label,
                    data: data,
                    backgroundColor: `hsla(${(i * 45) % 360}, 70%, 60%, 0.5)`,
                    borderColor: `hsl(${(i * 45) % 360}, 70%, 60%)`,
                    borderWidth: 1,
                    borderRadius: 4,
                    barPercentage: 0.8
                }));
                timelineChart.update();
            }
        } catch (e) { console.error("Error fetching timeline:", e); }
    };

    // Close sidebar on click outside on mobile
    window.onclick = (e) => {
        if (window.innerWidth < 1024 && !elements.detailCard.contains(e.target) && !elements.deviceTableBody.contains(e.target)) {
            elements.detailCard.classList.remove('open');
        }
    };
});
