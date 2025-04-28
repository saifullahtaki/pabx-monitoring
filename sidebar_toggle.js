async function updateRole(userId, role) {
    try {
        const response = await fetch(`/admin/update_role/${userId}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: `role=${encodeURIComponent(role)}`
        });
        const data = await response.json();
        
        const messageDiv = document.createElement('div');
        messageDiv.className = data.success ? 'success' : 'error';
        messageDiv.textContent = data.message;
        const flashMessages = document.querySelector('.flash-messages') || document.createElement('div');
        if (!flashMessages.className.includes('flash-messages')) {
            flashMessages.className = 'flash-messages';
            document.querySelector('.main-content').prepend(flashMessages);
        }
        flashMessages.appendChild(messageDiv);
        
        setTimeout(() => {
            messageDiv.style.opacity = '0';
            setTimeout(() => messageDiv.remove(), 500);
        }, 5000);
    } catch (error) {
        console.error('Error updating role:', error);
    }
}

document.addEventListener('DOMContentLoaded', () => {
    // Flash messages fade-out
    const flashMessages = document.querySelectorAll('.flash-messages .success, .flash-messages .error');
    flashMessages.forEach(message => {
        setTimeout(() => {
            message.style.opacity = '0';
            setTimeout(() => message.remove(), 500);
        }, 5000);
    });

    // Initialize sidebar state
    const isMinimized = localStorage.getItem('sidebarMinimized') === 'true';
    const body = document.body;
    const toggleBtn = document.querySelector('.toggle-btn');
    
    if (isMinimized) {
        body.classList.add('minimized-sidebar');
        if (toggleBtn) {
            toggleBtn.innerHTML = '<i class="fas fa-chevron-right"></i>';
        }
    } else {
        body.classList.remove('minimized-sidebar');
        if (toggleBtn) {
            toggleBtn.innerHTML = '<i class="fas fa-chevron-left"></i>';
        }
    }

    // Sidebar toggle functionality
    if (toggleBtn) {
        toggleBtn.addEventListener('click', () => {
            body.classList.toggle('minimized-sidebar');
            const isNowMinimized = body.classList.contains('minimized-sidebar');
            toggleBtn.innerHTML = isNowMinimized ? '<i class="fas fa-chevron-right"></i>' : '<i class="fas fa-chevron-left"></i>';
            localStorage.setItem('sidebarMinimized', isNowMinimized);
        });
    }
});
