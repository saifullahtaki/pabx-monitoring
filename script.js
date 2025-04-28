let refreshIntervalId = null;

// Utility function to format duration from seconds to HH:MM:SS
function formatDuration(seconds) {
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = seconds % 60;
    return `${String(hours).padStart(2, '0')}:${String(minutes).padStart(2, '0')}:${String(secs).padStart(2, '0')}`;
}

// Available table configurations
const tableConfigs = {
    'active-calls': {
        title: 'Active Calls',
        headers: ['Channel ID', 'Caller', 'Callee', 'Status', 'Duration', 'Packet Loss (%)', 'Jitter (ms)', 'RTT (ms)', 'Codec'],
        id: 'active-calls',
        dataKey: 'calls',
        renderRow: call => `
            <tr>
                <td>${call.channel_id || 'N/A'}</td>
                <td>${call.caller}</td>
                <td>${call.callee}</td>
                <td>${call.status}</td>
                <td>${formatDuration(call.duration)}</td>
                <td>${call.packet_loss || 0}</td>
                <td>${call.jitter || 0}</td>
                <td>${call.rtt || 0}</td>
                <td>${call.codec || 'Unknown'}</td>
            </tr>
        `
    },
    'current-channels': {
        title: 'Current Channels',
        headers: ['Channel', 'Location', 'Application', 'Duration'],
        id: 'current-channels',
        dataKey: 'channels',
        renderRow: channel => {
            const durationSeconds = channel.duration.split(':').reduce((acc, time, index) => {
                return acc + parseInt(time) * Math.pow(60, 2 - index);
            }, 0);
            return `
                <tr>
                    <td>${channel.channel}</td>
                    <td>${channel.location}</td>
                    <td>${channel.application}</td>
                    <td>${formatDuration(durationSeconds)}</td>
                </tr>
            `;
        }
    },
    'pjsip-endpoints': {
        title: 'PJSIP Endpoints',
        headers: ['Endpoint', 'State', 'AOR', 'Auth', 'Transport'],
        id: 'pjsip-endpoints',
        dataKey: 'endpoints',
        renderRow: endpoint => `
            <tr>
                <td>${endpoint.endpoint}</td>
                <td>${endpoint.state}</td>
                <td>${endpoint.aor}</td>
                <td>${endpoint.auth}</td>
                <td>${endpoint.transport}</td>
            </tr>
        `
    },
    'pjsip-contacts': {
        title: 'PJSIP Contacts',
        headers: ['Contact', 'Hash', 'Status', 'RTT (ms)'],
        id: 'pjsip-contacts',
        dataKey: 'contacts',
        renderRow: contact => `
            <tr>
                <td>${contact.contact}</td>
                <td>${contact.hash}</td>
                <td>${contact.status}</td>
                <td>${contact.rtt}</td>
            </tr>
        `
    },
    'call-status': {
        title: 'Call Status',
        headers: ['Extension', 'Status', 'Packet Loss (%)'],
        id: 'call-status',
        dataKey: 'phones',
        renderRow: phone => `
            <tr>
                <td>${phone.extension}</td>
                <td class="${phone.status.includes('Avail') ? 'status-online' : 'status-offline'}">${phone.status}</td>
                <td>${phone.packet_loss}</td>
            </tr>
        `
    },
    'phone-status': {
        title: 'Phone Status',
        headers: ['Extension', 'Number', 'Name', 'Location', 'IP', 'Status', 'Actions'],
        id: 'phone-status',
        dataKey: 'phone_status',
        renderRow: phone => `
            <tr>
                <td>${phone.extension}</td>
                <td>${phone.number}</td>
                <td>${phone.name}</td>
                <td>${phone.location}</td>
                <td>${phone.ip}</td>
                <td class="${phone.status === 'Active' ? 'status-online' : 'status-offline'}">${phone.status}</td>
                <td>
                    <button class="btn btn-warning" onclick="showModifyPhoneStatusModal('${phone.id}', '${phone.extension}', '${phone.number}', '${phone.name}', '${phone.location}', '${phone.ip}')">
                        <i class="fas fa-edit"></i>
                    </button>
                    <a href="{{ url_for('remove_phone_status', entry_id='${phone.id}') }}" class="btn btn-danger" onclick="return confirm('Are you sure you want to remove this entry?')">
                        <i class="fas fa-trash-alt"></i>
                    </a>
                </td>
            </tr>
        `
    }
};

// Fetch real-time data
async function fetchData() {
    try {
        const response = await fetch('/api/call_data');
        const data = await response.json();
        
        if (data.error) {
            console.error('Error fetching data:', data.error);
            return;
        }

        console.log('Fetched data:', data); // Debugging log

        // Update all visible tables
        Object.keys(tableConfigs).forEach(key => {
            const config = tableConfigs[key];
            const tableBody = document.getElementById(config.id);
            if (tableBody) {
                console.log(`Updating table ${config.id} with ${data[config.dataKey].length} rows`); // Debugging log
                tableBody.innerHTML = data[config.dataKey].map(config.renderRow).join('');
            }
        });
    } catch (e) {
        console.error('Error fetching data:', e);
    }
}

// Function to fetch locations for the dropdown
async function fetchLocations() {
    try {
        const response = await fetch('/api/locations');
        const data = await response.json();
        const locationSelects = document.querySelectorAll('.location-select');
        locationSelects.forEach(select => {
            const currentValue = select.value;
            select.innerHTML = data.locations.map(loc => `
                <option value="${loc.name}" ${loc.name === currentValue ? 'selected' : ''}>${loc.name}</option>
            `).join('');
        });
    } catch (e) {
        console.error('Error fetching locations:', e);
    }
}

// Function to set refresh interval
function setRefreshInterval() {
    const intervalSelect = document.getElementById('refresh-interval');
    if (intervalSelect) {
        const interval = parseInt(intervalSelect.value);
        if (refreshIntervalId) {
            clearInterval(refreshIntervalId);
        }
        refreshIntervalId = setInterval(() => {
            fetchData();
            fetchLocations();
        }, interval);
        console.log(`Set refresh interval to ${interval}ms`); // Debugging log
        // Trigger immediate fetch to ensure data is populated
        fetchData();
        fetchLocations();
    }
}

// Function to render a table
function renderTable(key, isMinimized = false) {
    const config = tableConfigs[key];
    return `
        <div class="table-container" data-table="${key}">
            <div class="card">
                <div class="card-header">
                    <div class="flex items-center gap-2">
                        <span class="drag-handle" draggable="true"><i class="fas fa-grip-vertical"></i></span>
                        <h2>${config.title}</h2>
                    </div>
                    <div>
                        <button class="btn minimize-btn" onclick="toggleMinimizeTable('${key}')">
                            <i class="fas ${isMinimized ? 'fa-plus' : 'fa-minus'}"></i>
                        </button>
                        <button class="btn remove-btn" onclick="removeTable('${key}')">
                            <i class="fas fa-times"></i>
                        </button>
                    </div>
                </div>
                <div class="table-wrapper ${isMinimized ? 'hidden' : ''}">
                    <table>
                        <thead>
                            <tr>
                                ${config.headers.map(header => `<th>${header}</th>`).join('')}
                            </tr>
                        </thead>
                        <tbody id="${config.id}"></tbody>
                    </table>
                </div>
            </div>
        </div>
    `;
}

// Function to add a table
function addTable(key) {
    const container = document.getElementById('dashboard-tables');
    if (container && !document.querySelector(`[data-table="${key}"]`)) {
        container.insertAdjacentHTML('beforeend', renderTable(key));
        updateTableList();
        fetchData();
        initializeDragAndDrop();
    }
}

// Function to remove a table
function removeTable(key) {
    const table = document.querySelector(`[data-table="${key}"]`);
    if (table) {
        table.remove();
        updateTableList();
    }
}

// Function to toggle minimize/expand
function toggleMinimizeTable(key) {
    const table = document.querySelector(`[data-table="${key}"]`);
    if (table) {
        table.classList.toggle('minimized');
        const tableWrapper = table.querySelector('.table-wrapper');
        tableWrapper.classList.toggle('hidden');
        const btn = table.querySelector('.minimize-btn i');
        btn.className = table.classList.contains('minimized') ? 'fas fa-plus' : 'fas fa-minus';
        updateMinimizedTables();
        // Fetch data immediately if expanding
        if (!table.classList.contains('minimized')) {
            fetchData();
        }
    }
}

// Function to update localStorage with current tables
function updateTableList() {
    const tables = Array.from(document.querySelectorAll('.table-container')).map(container => container.dataset.table);
    localStorage.setItem('dashboardTables', JSON.stringify(tables));
}

// Function to update minimized tables in localStorage
function updateMinimizedTables() {
    const minimizedTables = Array.from(document.querySelectorAll('.table-container.minimized')).map(container => container.dataset.table);
    localStorage.setItem('minimizedTables', JSON.stringify(minimizedTables));
}

// Function to initialize drag-and-drop functionality
function initializeDragAndDrop() {
    const handles = document.querySelectorAll('.drag-handle');
    handles.forEach(handle => {
        handle.addEventListener('dragstart', (e) => {
            const tableContainer = handle.closest('.table-container');
            e.dataTransfer.setData('text/plain', tableContainer.dataset.table);
            tableContainer.classList.add('dragging');
        });

        handle.addEventListener('dragend', () => {
            const tableContainer = handle.closest('.table-container');
            tableContainer.classList.remove('dragging');
        });
    });

    const tableContainers = document.querySelectorAll('.table-container');
    tableContainers.forEach(container => {
        container.addEventListener('dragover', (e) => {
            e.preventDefault();
            const draggingTable = document.querySelector('.dragging');
            if (!draggingTable) return;

            const rect = container.getBoundingClientRect();
            const midY = rect.top + rect.height / 2;
            const isAbove = e.clientY < midY;

            if (isAbove) {
                container.before(draggingTable);
            } else {
                container.after(draggingTable);
            }
        });

        container.addEventListener('drop', (e) => {
            e.preventDefault();
            updateTableList();
        });

        container.addEventListener('dragenter', (e) => {
            e.preventDefault();
        });
    });
}

// Function to show add table modal
function showAddTableModal() {
    const modal = document.getElementById('add-table-modal');
    const overlay = document.getElementById('modal-overlay');
    if (modal && overlay) {
        const select = modal.querySelector('select');
        select.innerHTML = '';
        const currentTables = Array.from(document.querySelectorAll('.table-container')).map(container => container.dataset.table);
        Object.keys(tableConfigs).forEach(key => {
            if (!currentTables.includes(key)) {
                select.innerHTML += `<option value="${key}">${tableConfigs[key].title}</option>`;
            }
        });
        modal.style.display = 'block';
        overlay.style.display = 'block';
    }
}

// Function to hide add table modal
function hideAddTableModal() {
    const modal = document.getElementById('add-table-modal');
    const overlay = document.getElementById('modal-overlay');
    if (modal && overlay) {
        modal.style.display = 'none';
        overlay.style.display = 'none';
    }
}

// Function to show modify phone status modal
function showModifyPhoneStatusModal(entryId, extension, number, name, location, ip) {
    const modal = document.getElementById('modify-phone-status-modal');
    const overlay = document.getElementById('modal-overlay');
    if (modal && overlay) {
        modal.querySelector('form').action = `/modify_phone_status/${entryId}`;
        modal.querySelector('#modify-extension').value = extension;
        modal.querySelector('#modify-number').value = number;
        modal.querySelector('#modify-name').value = name;
        modal.querySelector('#modify-location').value = location;
        modal.querySelector('#modify-ip').value = ip;
        fetchLocations(); // Ensure locations are updated
        modal.style.display = 'block';
        overlay.style.display = 'block';
    }
}

// Function to hide modify phone status modal
function hideModifyPhoneStatusModal() {
    const modal = document.getElementById('modify-phone-status-modal');
    const overlay = document.getElementById('modal-overlay');
    if (modal && overlay) {
        modal.style.display = 'none';
        overlay.style.display = 'none';
    }
}

// Function to show edit location modal
function showEditLocationModal(locationId, currentName) {
    const modal = document.getElementById('edit-location-modal');
    const overlay = document.getElementById('modal-overlay');
    if (modal && overlay) {
        modal.querySelector('form').action = `/edit_location/${locationId}`;
        modal.querySelector('#edit-location-name').value = currentName;
        modal.style.display = 'block';
        overlay.style.display = 'block';
    }
}

// Function to hide edit location modal
function hideEditLocationModal() {
    const modal = document.getElementById('edit-location-modal');
    const overlay = document.getElementById('modal-overlay');
    if (modal && overlay) {
        modal.style.display = 'none';
        overlay.style.display = 'none';
    }
}

// Initial setup
document.addEventListener('DOMContentLoaded', () => {
    const refreshSelect = document.getElementById('refresh-interval');
    if (refreshSelect) {
        refreshSelect.addEventListener('change', setRefreshInterval);
        setRefreshInterval();
    }

    // Load saved tables and minimized states from localStorage
    const savedTables = JSON.parse(localStorage.getItem('dashboardTables') || '[]');
    const minimizedTables = JSON.parse(localStorage.getItem('minimizedTables') || '[]');
    const container = document.getElementById('dashboard-tables');
    if (container) {
        savedTables.forEach(key => {
            if (tableConfigs[key]) {
                container.insertAdjacentHTML('beforeend', renderTable(key, minimizedTables.includes(key)));
            }
        });
        fetchData();
        fetchLocations();
        initializeDragAndDrop();
    }

    // Add table button event
    const addBtn = document.getElementById('add-table-btn');
    if (addBtn) {
        addBtn.addEventListener('click', showAddTableModal);
    }

    // Modal form submission
    const modalForm = document.getElementById('add-table-form');
    if (modalForm) {
        modalForm.addEventListener('submit', (e) => {
            e.preventDefault();
            const select = modalForm.querySelector('select');
            addTable(select.value);
            hideAddTableModal();
        });
    }

    // Modal cancel button
    const cancelBtn = document.querySelector('#add-table-modal .btn-danger');
    if (cancelBtn) {
        cancelBtn.addEventListener('click', hideAddTableModal);
    }

    // Modify phone status modal submission
    const modifyForm = document.getElementById('modify-phone-status-form');
    if (modifyForm) {
        modifyForm.addEventListener('submit', (e) => {
            e.preventDefault();
            const form = document.getElementById('modify-phone-status-form');
            const formData = new FormData(form);
            fetch(form.action, {
                method: 'POST',
                body: formData
            }).then(response => {
                if (response.ok) {
                    window.location.reload();
                }
            });
        });
    }

    // Modify phone status modal cancel button
    const modifyCancelBtn = document.querySelector('#modify-phone-status-modal .btn-danger');
    if (modifyCancelBtn) {
        modifyCancelBtn.addEventListener('click', hideModifyPhoneStatusModal);
    }

    // Edit location modal submission
    const editLocationForm = document.getElementById('edit-location-form');
    if (editLocationForm) {
        editLocationForm.addEventListener('submit', (e) => {
            e.preventDefault();
            const form = document.getElementById('edit-location-form');
            const formData = new FormData(form);
            fetch(form.action, {
                method: 'POST',
                body: formData
            }).then(response => {
                if (response.ok) {
                    fetchLocations(); // Update dropdowns
                    window.location.reload();
                }
            });
        });
    }

    // Edit location modal cancel button
    const editLocationCancelBtn = document.querySelector('#edit-location-modal .btn-danger');
    if (editLocationCancelBtn) {
        editLocationCancelBtn.addEventListener('click', hideEditLocationModal);
    }
});

// Expose functions to global scope for inline event handlers
window.removeTable = removeTable;
window.toggleMinimizeTable = toggleMinimizeTable;
window.showAddTableModal = showAddTableModal;
window.hideAddTableModal = hideAddTableModal;
window.showModifyPhoneStatusModal = showModifyPhoneStatusModal;
window.hideModifyPhoneStatusModal = hideModifyPhoneStatusModal;
window.showEditLocationModal = showEditLocationModal;
window.hideEditLocationModal = hideEditLocationModal;
