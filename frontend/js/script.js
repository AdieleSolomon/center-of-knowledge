// Spiritual-center/public/js/script.js
// Enhanced JavaScript for Spiritual Center Web Application
// Use the configured API base
let API_BASE = window.API_BASE;
console.log('🔧 API Base URL:', API_BASE);

        // Global state
        let currentUser = null;
        let authToken = localStorage.getItem('authToken');

        // Connection status monitoring
        let connectionStatus = {
            backend: false,
            database: false,
            lastCheck: null
        };

        // DOM Elements
        const authModal = document.getElementById('authModal');
        const userInfo = document.getElementById('userInfo');
        const authButtons = document.getElementById('authButtons');
        const userName = document.getElementById('userName');
        const userAvatar = document.getElementById('userAvatar');
        const adminPanel = document.getElementById('adminPanel');
        const contentContainer = document.getElementById('contentContainer');
        const mobileMenu = document.getElementById('mobileMenu');
        const mobileMenuBtn = document.getElementById('mobileMenuBtn');
        const mobileMenuClose = document.getElementById('mobileMenuClose');

        // Enhanced Debug function
        function debugLog(message, data = null) {
            const timestamp = new Date().toISOString();
            console.log(`🔍 [${timestamp}] ${message}`, data || '');
        }

        // Initialize app
        document.addEventListener('DOMContentLoaded', function() {
            debugLog('App initializing...');
            debugLog('Auth token exists:', !!authToken);
            
            // Show connection status
            showConnectionStatus('Checking server connection...', 'info');
            
            // Test backend first
            testBackendConnection().then(success => {
                if (success) {
                    if (authToken) {
                        debugLog('Token found in localStorage');
                        validateTokenAndLoadUser();
                    } else {
                        debugLog('No token found, loading public content');
                        loadPublicContent();
                    }
                } else {
                    // If backend fails, show error and try public content
                    showConnectionStatus('Backend server not available. Showing limited functionality.', 'error');
                    loadPublicContent();
                }
            });
            
            setupEventListeners();
        });

        // Enhanced backend connection test - FIXED PORT
        async function testBackendConnection() {
            try {
                debugLog('Testing backend connection to:', `${API_BASE}/test`);
                
                const controller = new AbortController();
                const timeoutId = setTimeout(() => controller.abort(), 5000); // 5 second timeout
                
                const response = await fetch(`${API_BASE}/test`, {
                    method: 'GET',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    signal: controller.signal
                });
                
                clearTimeout(timeoutId);
                
                debugLog('Backend response status:', response.status);
                
                if (!response.ok) {
                    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                }
                
                const data = await response.json();
                debugLog('Backend connection successful:', data);
                
                connectionStatus.backend = true;
                connectionStatus.lastCheck = new Date();
                
                showConnectionStatus('Connected to server successfully!', 'success');
                return true;
                
            } catch (error) {
                console.error('❌ Backend connection failed:', error);
                connectionStatus.backend = false;
                connectionStatus.lastCheck = new Date();
                
                let errorMessage = 'Cannot connect to server. ';
                
                if (error.name === 'AbortError') {
                    errorMessage += 'Request timeout. Server might be down or not responding.';
                } else if (error.message.includes('Failed to fetch')) {
                    errorMessage += 'Network error. Check if backend is running on port 5000.'; // FIXED PORT
                } else {
                    errorMessage += error.message;
                }
                
                showConnectionStatus(errorMessage, 'error');
                
                // Show troubleshooting tips
                showTroubleshootingTips();
                return false;
            }
        }

        // Show connection status to user
        function showConnectionStatus(message, type) {
            // Remove existing status message
            const existingStatus = document.getElementById('connectionStatus');
            if (existingStatus) {
                existingStatus.remove();
            }
            
            const statusDiv = document.createElement('div');
            statusDiv.id = 'connectionStatus';
            statusDiv.style.cssText = `
                position: fixed;
                top: 10px;
                left: 50%;
                transform: translateX(-50%);
                padding: 12px 20px;
                border-radius: 5px;
                color: white;
                z-index: 10001;
                font-weight: 500;
                box-shadow: 0 4px 12px rgba(0,0,0,0.3);
                max-width: 80%;
                text-align: center;
                backdrop-filter: blur(10px);
                border: 1px solid rgba(255,255,255,0.2);
            `;
            
            if (type === 'success') {
                statusDiv.style.background = 'linear-gradient(135deg, #4CAF50, #45a049)';
            } else if (type === 'error') {
                statusDiv.style.background = 'linear-gradient(135deg, #f44336, #d32f2f)';
            } else {
                statusDiv.style.background = 'linear-gradient(135deg, #2196F3, #1976D2)';
            }
            
            statusDiv.innerHTML = `
                <div style="display: flex; align-items: center; justify-content: center; gap: 10px;">
                    <i class="fas ${type === 'success' ? 'fa-check-circle' : type === 'error' ? 'fa-exclamation-triangle' : 'fa-info-circle'}"></i>
                    <span>${message}</span>
                    <button onclick="this.parentElement.parentElement.remove()" style="background: none; border: none; color: white; cursor: pointer; margin-left: 10px;">
                        <i class="fas fa-times"></i>
                    </button>
                </div>
            `;
            
            document.body.appendChild(statusDiv);
            
            // Auto-remove success messages after 5 seconds
            if (type === 'success') {
                setTimeout(() => {
                    if (document.body.contains(statusDiv)) {
                        statusDiv.remove();
                    }
                }, 5000);
            }
        }

        // Show troubleshooting tips - FIXED PORT
        function showTroubleshootingTips() {
            const tips = `
                <div style="background: rgba(255,255,255,0.1); padding: 20px; border-radius: 10px; margin: 20px 0; border-left: 4px solid #f44336;">
                    <h4 style="margin-top: 0; color: #ff6b6b;">Troubleshooting Tips:</h4>
                    <ol style="text-align: left; margin: 0; padding-left: 20px;">
                        <li>Make sure the backend server is running on port 5000</li>
                        <li>Check if MySQL database is running</li>
                        <li>Verify database credentials in .env file</li>
                        <li>Try refreshing the page</li>
                        <li>Check browser console for detailed errors (F12)</li>
                    </ol>
                    <button onclick="retryConnection()" class="btn" style="margin-top: 15px;">
                        <i class="fas fa-sync-alt"></i> Retry Connection
                    </button>
                </div>
            `;
            
            // Add tips to content container if it exists
            if (contentContainer) {
                contentContainer.innerHTML = tips + contentContainer.innerHTML;
            }
        }

        // Retry connection function
        function retryConnection() {
            debugLog('Retrying connection...');
            showConnectionStatus('Retrying connection...', 'info');
            
            testBackendConnection().then(success => {
                if (success) {
                    if (authToken) {
                        validateTokenAndLoadUser();
                    } else {
                        loadPublicContent();
                    }
                }
            });
        }

        // Enhanced token validation
        async function validateTokenAndLoadUser() {
            try {
                if (!authToken) {
                    throw new Error('No token found');
                }
                
                // Basic token validation
                const payload = JSON.parse(atob(authToken.split('.')[1]));
                const currentTime = Date.now() / 1000;
                
                if (payload.exp < currentTime) {
                    throw new Error('Token expired');
                }
                
                currentUser = payload;
                debugLog('Token validated, user:', currentUser);
                
                updateUI();
                loadContent();
                
                if (currentUser.role === 'admin') {
                    debugLog('Admin user detected, loading admin data');
                    loadAdminData();
                }
                
            } catch (error) {
                console.error('❌ Invalid token:', error);
                localStorage.removeItem('authToken');
                authToken = null;
                currentUser = null;
                updateUI();
                loadPublicContent();
                showMessage('Session expired. Please login again.', 'error');
            }
        }

        function setupEventListeners() {
            // Auth forms
            const loginForm = document.getElementById('loginForm');
            const registerForm = document.getElementById('registerForm');
            const contactForm = document.getElementById('contactForm');
            
            if (loginForm) loginForm.addEventListener('submit', handleLogin);
            if (registerForm) registerForm.addEventListener('submit', handleRegister);
            if (contactForm) contactForm.addEventListener('submit', handleContact);
            
            // Admin forms
            const uploadForm = document.getElementById('uploadForm');
            const contentType = document.getElementById('contentType');
            
            if (uploadForm) {
                uploadForm.addEventListener('submit', handleUpload);
            }
            if (contentType) {
                contentType.addEventListener('change', handleContentTypeChange);
            }
            
            // Mobile menu
            if (mobileMenuBtn) {
                mobileMenuBtn.addEventListener('click', openMobileMenu);
            }
            if (mobileMenuClose) {
                mobileMenuClose.addEventListener('click', closeMobileMenu);
            }
            
            // Auth modal close when clicking outside
            if (authModal) {
                authModal.addEventListener('click', function(e) {
                    if (e.target === authModal) {
                        closeAuthModal();
                    }
                });
            }

            // Password strength indicator
            const registerPassword = document.getElementById('registerPassword');
            if (registerPassword) {
                registerPassword.addEventListener('input', updatePasswordStrength);
            }

            // Close mobile menu when clicking on links
            document.querySelectorAll('.mobile-nav-links a').forEach(link => {
                link.addEventListener('click', closeMobileMenu);
            });

            debugLog('Event listeners setup complete');
        }

        // Mobile menu functions
        function openMobileMenu() {
            if (mobileMenu) {
                mobileMenu.classList.add('active');
                document.body.style.overflow = 'hidden';
            }
        }

        function closeMobileMenu() {
            if (mobileMenu) {
                mobileMenu.classList.remove('active');
                document.body.style.overflow = '';
            }
        }

        // Auth functions
        function openAuthModal() {
            debugLog('Opening auth modal');
            if (authModal) {
                authModal.style.display = 'flex';
                document.body.style.overflow = 'hidden';
            }
        }

        function closeAuthModal() {
            debugLog('Closing auth modal');
            if (authModal) {
                authModal.style.display = 'none';
                document.body.style.overflow = '';
                
                const loginForm = document.getElementById('loginForm');
                const registerForm = document.getElementById('registerForm');
                if (loginForm) loginForm.reset();
                if (registerForm) registerForm.reset();
            }
        }

        function switchAuthTab(tab) {
            debugLog('Switching to tab:', tab);
            document.querySelectorAll('.auth-tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.auth-form').forEach(f => f.classList.remove('active'));
            
            const activeTab = document.querySelector(`.auth-tab[onclick="switchAuthTab('${tab}')"]`);
            const activeForm = document.getElementById(`${tab}Form`);
            
            if (activeTab) activeTab.classList.add('active');
            if (activeForm) activeForm.classList.add('active');
        }

        // Enhanced login handler
        async function handleLogin(e) {
            e.preventDefault();
            
            const email = document.getElementById('loginEmail').value;
            const password = document.getElementById('loginPassword').value;
            
            debugLog('Login attempt with email:', email);
            
            if (!email || !password) {
                showMessage('Please enter both email and password', 'error');
                return;
            }

            const loginBtn = document.querySelector('.login-btn');
            const originalText = loginBtn.innerHTML;
            loginBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Signing In...';
            loginBtn.disabled = true;
            
            try {
                const response = await fetch(`${API_BASE}/login`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ email, password })
                });
                
                const data = await response.json();
                debugLog('Login response:', data);
                
                if (response.ok) {
                    authToken = data.token;
                    localStorage.setItem('authToken', authToken);
                    currentUser = data.user;
                    
                    debugLog('Login successful, user role:', currentUser.role);
                    
                    updateUI();
                    loadContent();
                    closeAuthModal();
                    
                    if (currentUser.role === 'admin') {
                        debugLog('Loading admin panel');
                        loadAdminData();
                    }
                    
                    showMessage(`Welcome back, ${currentUser.username}!`, 'success');
                } else {
                    showMessage(data.error || 'Login failed. Please try again.', 'error');
                }
            } catch (error) {
                console.error('❌ Login error:', error);
                showMessage('Network error. Please check your connection and try again.', 'error');
            } finally {
                loginBtn.innerHTML = originalText;
                loginBtn.disabled = false;
            }
        }

        // Enhanced registration handler
        async function handleRegister(e) {
            e.preventDefault();
            
            const username = document.getElementById('registerUsername').value;
            const email = document.getElementById('registerEmail').value;
            const password = document.getElementById('registerPassword').value;
            const confirmPassword = document.getElementById('registerConfirmPassword').value;
            
            if (password !== confirmPassword) {
                showMessage('Passwords do not match!', 'error');
                return;
            }
            
            if (password.length < 6) {
                showMessage('Password must be at least 6 characters long', 'error');
                return;
            }
            
            const registerBtn = document.querySelector('.register-btn');
            const originalText = registerBtn.innerHTML;
            registerBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Creating Account...';
            registerBtn.disabled = true;
            
            try {
                const response = await fetch(`${API_BASE}/register`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ username, email, password })
                });
                
                const data = await response.json();
                debugLog('Registration response:', data);
                
                if (response.ok) {
                    showMessage('Registration successful! Please wait for admin approval.', 'success');
                    document.getElementById('registerForm').reset();
                    switchAuthTab('login');
                } else {
                    showMessage(data.error || 'Registration failed. Please try again.', 'error');
                }
            } catch (error) {
                console.error('❌ Registration error:', error);
                showMessage('Network error. Please check your connection and try again.', 'error');
            } finally {
                registerBtn.innerHTML = originalText;
                registerBtn.disabled = false;
            }
        }

        function logout() {
            debugLog('Logging out user');
            localStorage.removeItem('authToken');
            authToken = null;
            currentUser = null;
            updateUI();
            closeMobileMenu();
            loadPublicContent();
            showMessage('Logged out successfully', 'success');
        }

        function updateUI() {
            if (currentUser) {
                debugLog('Updating UI for logged in user:', currentUser.username);
                userInfo.style.display = 'flex';
                authButtons.style.display = 'none';
                userName.textContent = currentUser.username;
                userAvatar.textContent = currentUser.username.charAt(0).toUpperCase();
                
                // Update mobile UI
                document.getElementById('mobileUserInfo').style.display = 'block';
                document.getElementById('mobileAuthButtons').style.display = 'none';
                document.getElementById('mobileUserName').textContent = currentUser.username;
                document.getElementById('mobileUserAvatar').textContent = currentUser.username.charAt(0).toUpperCase();
                
                if (currentUser.role === 'admin') {
                    debugLog('Showing admin panel');
                    adminPanel.style.display = 'block';
                } else {
                    adminPanel.style.display = 'none';
                }
            } else {
                debugLog('Updating UI for logged out user');
                userInfo.style.display = 'none';
                authButtons.style.display = 'block';
                adminPanel.style.display = 'none';
                
                document.getElementById('mobileUserInfo').style.display = 'none';
                document.getElementById('mobileAuthButtons').style.display = 'block';
            }
        }

        // Enhanced content loading with better error handling
        async function loadContent() {
            if (!authToken) {
                showLoginPrompt();
                return;
            }
            
            try {
                debugLog('Loading authenticated content...');
                
                const response = await fetch(`${API_BASE}/content`, {
                    headers: {
                        'Authorization': `Bearer ${authToken}`,
                        'Content-Type': 'application/json'
                    }
                });
                
                debugLog('Content response status:', response.status);
                
                if (response.ok) {
                    const content = await response.json();
                    debugLog('Content loaded successfully:', content.length + ' items');
                    renderContent(content);
                } else if (response.status === 401) {
                    // Token expired or invalid
                    debugLog('Token invalid, clearing and redirecting to public content');
                    localStorage.removeItem('authToken');
                    authToken = null;
                    currentUser = null;
                    updateUI();
                    showLoginPrompt();
                    showMessage('Session expired. Please login again.', 'error');
                } else {
                    throw new Error(`Failed to load content: ${response.status}`);
                }
            } catch (error) {
                console.error('❌ Content loading error:', error);
                contentContainer.innerHTML = `
                    <div class="content-item">
                        <div class="content-details">
                            <h3>Error Loading Content</h3>
                            <p>${error.message}</p>
                            <div style="display: flex; gap: 10px; margin-top: 15px;">
                                <button class="btn" onclick="loadContent()">
                                    <i class="fas fa-sync-alt"></i> Retry
                                </button>
                                <button class="btn-secondary" onclick="loadPublicContent()">
                                    <i class="fas fa-eye"></i> View Public Content
                                </button>
                            </div>
                        </div>
                    </div>
                `;
            }
        }

        async function loadPublicContent() {
            try {
                debugLog('Loading public content...');
                const response = await fetch(`${API_BASE}/content/public`);
                
                if (response.ok) {
                    const content = await response.json();
                    debugLog('Public content loaded:', content.length + ' items');
                    renderContent(content);
                } else {
                    showLoginPrompt();
                }
            } catch (error) {
                console.error('❌ Public content loading error:', error);
                showLoginPrompt();
            }
        }

        function showLoginPrompt() {
            if (contentContainer) {
                contentContainer.innerHTML = `
                    <div class="content-item">
                        <div class="content-details">
                            <h3>Please Login to Access Resources</h3>
                            <p>Create an account or login to access our spiritual resources, videos, and teachings.</p>
                            <button class="btn" onclick="openAuthModal()">Login/Register</button>
                        </div>
                    </div>
                `;
            }
        }

        function renderContent(content) {
            if (!contentContainer) return;
            
            if (content.length === 0) {
                contentContainer.innerHTML = `
                    <div class="content-item">
                        <div class="content-details">
                            <h3>No Content Available Yet</h3>
                            <p>Check back later for new spiritual resources or contact the administrator.</p>
                            ${currentUser && currentUser.role === 'admin' ? 
                                `<button class="btn" onclick="switchAdminTab('upload')">Upload Content</button>` : 
                                ''
                            }
                        </div>
                    </div>
                `;
                return;
            }
            
            contentContainer.innerHTML = content.map(item => createContentItem(item)).join('');
        }

        // Fixed content URL generation function - FIXED PORT
        function createContentItem(item) {
            let mediaContent = '';
            
            // Fix URL generation - handle cases where file_url might be null or already contain full URL
            let fileUrl = item.file_url;
            
            // If file_url exists and doesn't start with http, prepend the correct base
            if (fileUrl && !fileUrl.startsWith('http')) {
                // For uploads, we need to construct the full URL
                if (fileUrl.startsWith('/uploads/')) {
                    fileUrl = `http://localhost:5000${fileUrl}`; // FIXED PORT to 5000
                }
            }
            
            if (item.type === 'video') {
                mediaContent = `
                    <div class="video-container">
                        <video controls style="width: 100%; height: 100%;">
                            <source src="${fileUrl || ''}" type="video/mp4">
                            Your browser does not support the video tag.
                        </video>
                    </div>
                `;
            } else if (item.type === 'image') {
                mediaContent = `
                    <div class="content-img">
                        <img src="${fileUrl || ''}" alt="${item.title}" style="width: 100%; height: 100%; object-fit: cover;">
                    </div>
                `;
            } else if (item.type === 'writeup') {
                // For writeups, we don't need media content, just show the text
                mediaContent = `
                    <div class="content-img" style="background: linear-gradient(135deg, var(--secondary), var(--primary)); display: flex; align-items: center; justify-content: center; min-height: 200px;">
                        <i class="fas fa-file-alt" style="font-size: 3rem; color: var(--accent);"></i>
                    </div>
                `;
            }
            
            return `
                <div class="content-item">
                    ${mediaContent}
                    <div class="content-details">
                        <h3>${item.title || 'Untitled'}</h3>
                        <div class="content-date">Posted: ${new Date(item.created_at).toLocaleDateString()}</div>
                        <div class="content-author">By: ${item.author || 'Admin'}</div>
                        <p>${item.description || 'No description available.'}</p>
                        ${item.type === 'writeup' && item.content_text ? `
                            <div class="writeup-content" style="margin-top: 15px; padding: 15px; background: rgba(255,255,255,0.1); border-radius: 5px; border-left: 3px solid var(--accent);">
                                ${item.content_text}
                            </div>
                        ` : ''}
                        ${!currentUser ? `
                            <p style="color: var(--accent); font-size: 0.9rem; margin-top: 10px;">
                                <i class="fas fa-lock"></i> Login to access more resources
                            </p>
                        ` : ''}
                    </div>
                </div>
            `;
        }

        // WhatsApp message function
        function sendWhatsAppMessage() {
            const name = document.getElementById('contactName').value;
            const email = document.getElementById('contactEmail').value;
            const message = document.getElementById('contactMessage').value;
            
            if (!name || !email || !message) {
                showMessage('Please fill in all fields before sending via WhatsApp', 'error');
                return;
            }
            
            const whatsappMessage = `Hello, my name is ${name}. My email is ${email}. ${message}`;
            const encodedMessage = encodeURIComponent(whatsappMessage);
            const whatsappUrl = `https://wa.me/2349072560420?text=${encodedMessage}`;
            
            window.open(whatsappUrl, '_blank');
            showMessage('WhatsApp is opening with your message. Please send it to complete the process.', 'success');
        }

        // Admin functions
        function switchAdminTab(tab) {
            debugLog('Switching admin tab to:', tab);
            document.querySelectorAll('.admin-tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.admin-content').forEach(c => c.classList.remove('active'));
            
            const activeTab = document.querySelector(`.admin-tab[onclick="switchAdminTab('${tab}')"]`);
            const activeContent = document.getElementById(`${tab}Tab`);
            
            if (activeTab) activeTab.classList.add('active');
            if (activeContent) activeContent.classList.add('active');
        }

        function handleContentTypeChange() {
            const type = document.getElementById('contentType').value;
            const fileGroup = document.getElementById('fileUploadGroup');
            const textGroup = document.getElementById('contentTextGroup');
            
            if (type === 'writeup') {
                fileGroup.style.display = 'none';
                textGroup.style.display = 'block';
            } else {
                fileGroup.style.display = 'block';
                textGroup.style.display = 'none';
            }
        }

        async function handleUpload(e) {
            e.preventDefault();
            
            if (!currentUser || currentUser.role !== 'admin') {
                showMessage('Admin access required', 'error');
                return;
            }
            
            const formData = new FormData();
            formData.append('title', document.getElementById('contentTitle').value);
            formData.append('description', document.getElementById('contentDescription').value);
            formData.append('type', document.getElementById('contentType').value);
            formData.append('is_public', document.getElementById('contentPublic').checked);
            
            const type = document.getElementById('contentType').value;
            if (type === 'writeup') {
                formData.append('content_text', document.getElementById('contentText').value);
            } else {
                const fileInput = document.getElementById('contentFile');
                if (fileInput.files.length === 0) {
                    showMessage('Please select a file for upload', 'error');
                    return;
                }
                formData.append('file', fileInput.files[0]);
            }
            
            try {
                const response = await fetch(`${API_BASE}/content`, {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${authToken}`
                    },
                    body: formData
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    showMessage('Content uploaded successfully!', 'success');
                    document.getElementById('uploadForm').reset();
                    loadContent();
                    loadAdminData();
                } else {
                    showMessage(data.error, 'error');
                }
            } catch (error) {
                console.error('Upload error:', error);
                showMessage('Upload failed. Please try again.', 'error');
            }
        }

        async function loadAdminData() {
            if (!currentUser || currentUser.role !== 'admin') {
                debugLog('User is not admin, skipping admin data load');
                return;
            }
            
            debugLog('Loading admin data...');
            
            try {
                const [usersResponse, prayersResponse, contentResponse] = await Promise.all([
                    fetch(`${API_BASE}/users`, { headers: { 'Authorization': `Bearer ${authToken}` } }),
                    fetch(`${API_BASE}/prayer-requests`, { headers: { 'Authorization': `Bearer ${authToken}` } }),
                    fetch(`${API_BASE}/content`, { headers: { 'Authorization': `Bearer ${authToken}` } })
                ]);

                if (usersResponse.ok) {
                    const users = await usersResponse.json();
                    renderUsers(users);
                    updateAdminStats(users, null, null);
                }

                if (prayersResponse.ok) {
                    const prayers = await prayersResponse.json();
                    renderPrayers(prayers);
                    updateAdminStats(null, prayers, null);
                }

                if (contentResponse.ok) {
                    const content = await contentResponse.json();
                    updateAdminStats(null, null, content);
                }

                debugLog('Admin data loaded successfully');

            } catch (error) {
                console.error('❌ Admin data loading error:', error);
            }
        }

        function updateAdminStats(users, prayers, content) {
            if (users) {
                document.getElementById('totalUsers').textContent = users.length;
                const pendingApprovals = users.filter(user => !user.is_approved).length;
                document.getElementById('pendingApprovals').textContent = pendingApprovals;
            }
            
            if (prayers) {
                document.getElementById('pendingRequests').textContent = prayers.length;
            }
            
            if (content) {
                document.getElementById('totalContent').textContent = content.length;
                
                const contentTypes = {
                    video: content.filter(item => item.type === 'video').length,
                    image: content.filter(item => item.type === 'image').length,
                    writeup: content.filter(item => item.type === 'writeup').length
                };
                
                let popularType = 'None';
                let maxCount = 0;
                for (const [type, count] of Object.entries(contentTypes)) {
                    if (count > maxCount) {
                        maxCount = count;
                        popularType = type.charAt(0).toUpperCase() + type.slice(1);
                    }
                }
                
                document.getElementById('popularContent').textContent = popularType;
                document.getElementById('totalViews').textContent = content.length * 5;
                document.getElementById('activeUsers').textContent = Math.floor(content.length * 0.7);
            }
        }

        function renderUsers(users) {
            const usersList = document.getElementById('usersList');
            if (!usersList) return;
            
            usersList.innerHTML = users.map(user => `
                <div class="list-card">
                    <div class="list-row">
                        <div class="list-primary">
                            <strong>${user.username}</strong> (${user.email})<br>
                            <small>Role: ${user.role} | Approved: ${user.is_approved ? 'Yes' : 'No'} | Joined: ${new Date(user.created_at).toLocaleDateString()}</small>
                        </div>
                        <div class="list-actions">
                            ${!user.is_approved ? `<button class="btn" onclick="approveUser(${user.id})">Approve</button>` : ''}
                            <button class="btn-secondary" onclick="deleteUser(${user.id})">Delete</button>
                        </div>
                    </div>
                </div>
            `).join('');
        }

        function renderPrayers(prayers) {
            const prayersList = document.getElementById('prayersList');
            if (!prayersList) return;
            
            prayersList.innerHTML = prayers.map(prayer => `
                <div class="list-card">
                    <div class="list-row">
                        <div class="list-primary">
                            <strong>${prayer.name}</strong> (${prayer.email})<br>
                            <strong>Subject:</strong> ${prayer.subject}<br>
                            <strong>Message:</strong> ${prayer.message}<br>
                            <small>Status: ${prayer.status || 'Pending'} | Submitted: ${new Date(prayer.created_at).toLocaleDateString()}</small>
                        </div>
                        <div class="list-actions">
                            <button class="btn" onclick="markPrayerAsRead(${prayer.id})">Mark as Read</button>
                            <button class="btn-secondary" onclick="deletePrayer(${prayer.id})">Delete</button>
                        </div>
                    </div>
                </div>
            `).join('');
        }

        async function approveUser(userId) {
            try {
                const response = await fetch(`${API_BASE}/users/${userId}/approve`, {
                    method: 'PUT',
                    headers: {
                        'Authorization': `Bearer ${authToken}`,
                        'Content-Type': 'application/json'
                    }
                });
                
                if (response.ok) {
                    showMessage('User approved successfully!', 'success');
                    loadAdminData();
                } else {
                    showMessage('Failed to approve user', 'error');
                }
            } catch (error) {
                showMessage('Failed to approve user', 'error');
            }
        }

        async function deleteUser(userId) {
            if (confirm('Are you sure you want to delete this user?')) {
                try {
                    const response = await fetch(`${API_BASE}/users/${userId}`, {
                        method: 'DELETE',
                        headers: {
                            'Authorization': `Bearer ${authToken}`,
                            'Content-Type': 'application/json'
                        }
                    });
                    
                    if (response.ok) {
                        showMessage('User deleted successfully!', 'success');
                        loadAdminData();
                    } else {
                        showMessage('Failed to delete user', 'error');
                    }
                } catch (error) {
                    showMessage('Failed to delete user', 'error');
                }
            }
        }

        async function markPrayerAsRead(prayerId) {
            try {
                const response = await fetch(`${API_BASE}/prayer-requests/${prayerId}/read`, {
                    method: 'PUT',
                    headers: {
                        'Authorization': `Bearer ${authToken}`,
                        'Content-Type': 'application/json'
                    }
                });
                
                if (response.ok) {
                    showMessage('Prayer request marked as read!', 'success');
                    loadAdminData();
                } else {
                    showMessage('Failed to update prayer request', 'error');
                }
            } catch (error) {
                showMessage('Failed to update prayer request', 'error');
            }
        }

        async function deletePrayer(prayerId) {
            if (confirm('Are you sure you want to delete this prayer request?')) {
                try {
                    const response = await fetch(`${API_BASE}/prayer-requests/${prayerId}`, {
                        method: 'DELETE',
                        headers: {
                            'Authorization': `Bearer ${authToken}`,
                            'Content-Type': 'application/json'
                        }
                    });
                    
                    if (response.ok) {
                        showMessage('Prayer request deleted successfully!', 'success');
                        loadAdminData();
                    } else {
                        showMessage('Failed to delete prayer request', 'error');
                    }
                } catch (error) {
                    showMessage('Failed to delete prayer request', 'error');
                }
            }
        }

        // Contact form handler
        async function handleContact(e) {
            e.preventDefault();
            
            const name = document.getElementById('contactName').value;
            const email = document.getElementById('contactEmail').value;
            const subject = document.getElementById('contactSubject').value;
            const message = document.getElementById('contactMessage').value;
            const userId = currentUser ? currentUser.id : null;
            
            try {
                const response = await fetch(`${API_BASE}/prayer-requests`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ name, email, subject, message, userId })
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    showMessage('Prayer request submitted successfully! We will contact you soon.', 'success');
                    document.getElementById('contactForm').reset();
                } else {
                    showMessage(data.error, 'error');
                }
            } catch (error) {
                showMessage('Submission failed. Please try again.', 'error');
            }
        }

        // Utility functions
        function showMessage(message, type) {
            const toast = document.createElement('div');
            toast.style.cssText = `
                position: fixed;
                top: 20px;
                right: 20px;
                padding: 15px 20px;
                border-radius: 5px;
                color: white;
                z-index: 10000;
                font-weight: 500;
                box-shadow: 0 4px 12px rgba(0,0,0,0.15);
                transition: all 0.3s ease;
                max-width: 400px;
                word-wrap: break-word;
            `;
            
            toast.style.background = type === 'success' ? '#4CAF50' : '#f44336';
            toast.textContent = message;
            document.body.appendChild(toast);
            
            setTimeout(() => {
                toast.style.opacity = '0';
                setTimeout(() => {
                    if (document.body.contains(toast)) {
                        document.body.removeChild(toast);
                    }
                }, 300);
            }, 4000);
        }

        function updatePasswordStrength(e) {
            const password = e.target.value;
            const strengthBar = document.querySelector('.strength-bar');
            
            if (!strengthBar) return;
            
            let strength = 'weak';
            let strengthText = 'Weak';
            
            if (password.length >= 8) {
                strength = 'medium';
                strengthText = 'Medium';
            }
            if (password.length >= 12 && /[A-Z]/.test(password) && /[0-9]/.test(password) && /[^A-Za-z0-9]/.test(password)) {
                strength = 'strong';
                strengthText = 'Strong';
            }
            
            strengthBar.className = 'strength-bar strength-' + strength;
            strengthBar.setAttribute('title', strengthText);
        }

        // Smooth scrolling for navigation links
        document.querySelectorAll('a[href^="#"]').forEach(anchor => {
            anchor.addEventListener('click', function (e) {
                e.preventDefault();
                
                const targetId = this.getAttribute('href');
                if (targetId === '#') return;
                
                const targetElement = document.querySelector(targetId);
                if (targetElement) {
                    window.scrollTo({
                        top: targetElement.offsetTop - 70,
                        behavior: 'smooth'
                    });
                }
            });
        });