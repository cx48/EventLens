 // Current date
 document.getElementById('currentDate').textContent = new Date().toLocaleDateString('en-US', { 
    year: 'numeric', 
    month: 'long', 
    day: 'numeric' 
});

// Function to get severity color
function getSeverityColor(severity) {
    switch(severity) {
        case 'high': return 'bg-red-100 text-red-800';
        case 'medium': return 'bg-yellow-100 text-yellow-800';
        case 'low': return 'bg-green-100 text-green-800';
        default: return 'bg-gray-100 text-gray-800';
    }
}

// Function to render event cards
function renderEventCards(events, containerId) {
    const container = document.getElementById(containerId);
    container.innerHTML = '';
    
    events.forEach(event => {
        const severityColor = getSeverityColor(event.severity);
        
        const card = document.createElement('div');
        card.className = 'log-card p-4 rounded-lg border border-gray-200 relative';
        card.innerHTML = `
            <div class="flex justify-between items-start">
                <div>
                    <span class="inline-block px-3 py-1 rounded-full text-sm font-semibold ${severityColor} mb-2">
                        ${event.severity.charAt(0).toUpperCase() + event.severity.slice(1)}
                    </span>
                    <h3 class="text-lg font-semibold text-gray-800">${event.title} <span class="text-gray-500">(ID: ${event.id})</span></h3>
                    <p class="text-gray-600 mt-1">${event.description}</p>
                </div>
                <button class="copy-btn absolute top-3 right-3 text-gray-400 hover:text-blue-500" 
                        onclick="copyToClipboard('${event.id}', this)" 
                        title="Copy Event ID">
                    <i class="far fa-copy"></i>
                </button>
            </div>
        `;
        
        container.appendChild(card);
    });
}

// Function to render logon types
function renderLogonTypes() {
    const container = document.getElementById('logonTypes');
    container.innerHTML = '';
    
    logonTypeCodes.forEach(logonType => {
        const card = document.createElement('div');
        card.className = 'logon-type-card p-3 rounded-lg border border-gray-200';
        card.innerHTML = `
            <div class="flex items-start">
                <span class="inline-flex items-center justify-center h-8 w-8 rounded-full bg-blue-100 text-blue-800 font-bold mr-3 mt-1">
                    ${logonType.type}
                </span>
                <div>
                    <p class="text-gray-800">${logonType.description}</p>
                </div>
            </div>
        `;
        
        container.appendChild(card);
    });
}

// Function to render event providers
function renderEventProviders() {
    const container = document.getElementById('eventProviders');
    container.innerHTML = '';
    
    eventProviders.forEach(provider => {
        const card = document.createElement('div');
        card.className = 'p-4 rounded-lg border border-gray-200';
        card.innerHTML = `
            <h3 class="font-semibold text-gray-800 mb-2">
                <span class="provider-tag mr-2">${provider.name}</span>
            </h3>
            <p class="text-gray-600 mb-2">${provider.description}</p>
            <p class="text-sm text-gray-500">
                <span class="font-medium">Example Events:</span> ${provider.exampleEvents}
            </p>
        `;

        container.appendChild(card);
    });
}

// Initial render
renderEventCards(securityEvents, 'securityLogs');
renderEventCards(sysmonEvents, 'sysmonLogs');
renderEventCards(systemEvents, 'systemLogs');
renderLogonTypes();
renderEventProviders();

// Copy to clipboard function
function copyToClipboard(text, button) {
    navigator.clipboard.writeText(text).then(() => {
        // Change icon to checkmark temporarily
        const icon = button.querySelector('i');
        const originalClass = icon.className;
        
        icon.className = 'fas fa-check text-green-500';
        
        setTimeout(() => {
            icon.className = originalClass;
        }, 1500);
    });
}