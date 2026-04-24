document.addEventListener('DOMContentLoaded', () => {
    const scanBtn = document.getElementById('scanBtn');
    const btnText = document.getElementById('btnText');
    const loader = document.getElementById('loader');
    const subnetInput = document.getElementById('subnetInput');
    const deviceTableBody = document.getElementById('deviceTableBody');
    const statusBanner = document.getElementById('statusBanner');
    const errorMessage = document.getElementById('errorMessage');

    const updateUI = (isLoading) => {
        if (isLoading) {
            scanBtn.disabled = true;
            scanBtn.classList.add('opacity-75', 'cursor-not-allowed');
            btnText.textContent = 'Scanning...';
            loader.classList.remove('hidden');
            statusBanner.classList.add('hidden');
        } else {
            scanBtn.disabled = false;
            scanBtn.classList.remove('opacity-75', 'cursor-not-allowed');
            btnText.textContent = 'Start Scan';
            loader.classList.add('hidden');
        }
    };

    const showError = (msg) => {
        statusBanner.classList.remove('hidden');
        errorMessage.textContent = msg;
    };

    const performScan = async () => {
        const subnet = subnetInput.value.trim();
        if (!subnet) {
            showError('Please enter a valid subnet range (e.g., 192.168.1.0/24)');
            return;
        }

        updateUI(true);
        deviceTableBody.innerHTML = ''; // Clear previous results

        try {
            const response = await fetch(`/api/scan?subnet=${encodeURIComponent(subnet)}`);
            const result = await response.json();

            if (!response.ok) {
                throw new Error(result.detail || 'An error occurred during the scan');
            }

            if (result.data && result.data.length > 0) {
                renderDevices(result.data);
            } else {
                deviceTableBody.innerHTML = `
                    <tr>
                        <td colspan="4" class="px-8 py-20 text-center text-slate-500">
                            No devices found on this subnet.
                        </td>
                    </tr>
                `;
            }
        } catch (error) {
            console.error('Scan failed:', error);
            showError(error.message);
        } finally {
            updateUI(false);
        }
    };

    const renderDevices = (devices) => {
        deviceTableBody.innerHTML = devices.map((device, index) => `
            <tr class="hover:bg-white/5 transition-colors group">
                <td class="px-8 py-6">
                    <div class="flex items-center gap-3">
                        <div class="w-10 h-10 rounded-full bg-blue-500/10 flex items-center justify-center text-blue-400 group-hover:bg-blue-500 group-hover:text-white transition-all">
                            <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
                                <path fill-rule="evenodd" d="M3 5a2 2 0 012-2h10a2 2 0 012 2v8a2 2 0 01-2 2h-2.22l.123.489.804.804A1 1 0 0113 18H7a1 1 0 01-.707-1.707l.804-.804L7.22 15H5a2 2 0 01-2-2V5zm2 1h10v7H5V6z" clip-rule="evenodd" />
                            </svg>
                        </div>
                        <span class="font-medium">Device #${index + 1}</span>
                    </div>
                </td>
                <td class="px-8 py-6 font-mono text-blue-400">${device.ip}</td>
                <td class="px-8 py-6 font-mono text-slate-400">${device.mac}</td>
                <td class="px-8 py-6">
                    <span class="px-3 py-1 rounded-full bg-slate-800 text-slate-300 text-sm border border-white/5">
                        ${device.vendor}
                    </span>
                </td>
            </tr>
        `).join('');
    };

    scanBtn.addEventListener('click', performScan);
});
