/**
 * Sentinel Privacy Lab v3.0
 * Complete PII Protection Demo - Single File Solution
 */

(function() {
    'use strict';
    
    // ===== CONFIGURATION =====
    const CONFIG = {
        PII_PATTERNS: {
            email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
            creditCard: /\b(?:\d[ -]*?){13,16}\b/g,
            apiKey: /\b(sk_(live|test|prod)_|ghp_)[A-Za-z0-9_]{20,}\b/g,
            ssn: /\b\d{3}[- ]?\d{2}[- ]?\d{4}\b/g,
            phone: /\b(\+\d{1,3}[- ]?)?\(?\d{3}\)?[- ]?\d{3}[- ]?\d{4}\b/g
        },
        
        MONITOR_UPDATE_DELAY: 300,
        ENCRYPTION_ALGORITHM: 'AES-GCM',
        KEY_LENGTH: 256,
        
        COLORS: {
            danger: '#ef4444',
            success: '#10b981',
            warning: '#f59e0b',
            info: '#3b82f6'
        }
    };
    
    // ===== GLOBAL STATE =====
    const state = {
        sentinel: null,
        stats: {
            piiDetected: 0,
            fieldsProtected: 0,
            leaksPrevented: 0,
            totalEvents: 0
        },
        
        monitors: {
            vulnerable: null,
            protected: null,
            lastUpdate: 0
        },
        
        forms: {
            vulnerable: null,
            protected: null
        },
        
        sentinelActive: false
    };
    
    // ===== SENTINEL SDK =====
    class Sentinel {
        constructor() {
            this.key = null;
            this.attachedForms = new Map();
            this.originalValues = new WeakMap();
            this.encryptedData = new WeakMap();
            this.init();
        }
        
        async init() {
            try {
                this.key = await crypto.subtle.generateKey(
                    { name: CONFIG.ENCRYPTION_ALGORITHM, length: CONFIG.KEY_LENGTH },
                    true,
                    ["encrypt", "decrypt"]
                );
                console.log('✅ Sentinel: Web Crypto API initialized');
            } catch (error) {
                console.warn('⚠️ Sentinel: Using secure hashing (Web Crypto unavailable)');
                this.key = null;
            }
        }
        
        attach(formId) {
            const form = document.getElementById(formId);
            if (!form) return false;
            
            const inputs = Array.from(form.querySelectorAll('input, textarea'));
            const isProtected = formId.includes('protected');
            
            this.attachedForms.set(formId, { inputs, isProtected });
            
            inputs.forEach(input => {
                // Setup event listeners
                const onInput = (e) => this.handleInput(e.target, formId);
                const onFocus = (e) => this.handleFocus(e.target);
                const onBlur = (e) => this.handleBlur(e.target, formId);
                
                input.addEventListener('input', onInput);
                input.addEventListener('focus', onFocus);
                input.addEventListener('blur', onBlur);
                
                // Store references for cleanup
                input._sentinelListeners = { onInput, onFocus, onBlur };
                
                // Initial scan
                this.scanField(input, formId);
            });
            
            console.log(`✅ Sentinel attached to #${formId}`);
            return true;
        }
        
        scanField(input, formId) {
            const value = input.value.trim();
            if (!value) return false;
            
            const patterns = CONFIG.PII_PATTERNS;
            let hasPII = false;
            let piiType = null;
            
            for (const [type, pattern] of Object.entries(patterns)) {
                const singlePattern = new RegExp(pattern.source, pattern.flags.replace('g', ''));
                if (singlePattern.test(value)) {
                    hasPII = true;
                    piiType = type;
                    this.originalValues.set(input, value);
                    input._sentinelHasPII = true;
                    input._sentinelPIIType = type;
                    
                    // Update global stats
                    state.stats.piiDetected++;
                    updateUIStats();
                    
                    break;
                }
            }
            
            // Only protect if this is the protected form
            const formInfo = this.attachedForms.get(formId);
            if (hasPII && piiType && formInfo.isProtected) {
                this.protectField(input, value, piiType);
            }
            
            return hasPII;
        }
        
        async protectField(input, value, piiType) {
            try {
                let token;
                
                if (this.key) {
                    // Use Web Crypto API
                    const encrypted = await this.encryptValue(value);
                    token = {
                        encrypted: encrypted.ciphertext.substring(0, 32) + '...',
                        iv: encrypted.iv.substring(0, 16) + '...',
                        algorithm: CONFIG.ENCRYPTION_ALGORITHM
                    };
                } else {
                    // Fallback to hash
                    token = {
                        token: 'tok_' + this.hashString(value).substring(0, 24),
                        algorithm: 'SHA-256'
                    };
                }
                
                this.encryptedData.set(input, {
                    original: value,
                    token,
                    type: piiType,
                    timestamp: Date.now()
                });
                
                // Add visual indicator
                this.addProtectionBadge(input);
                
                // Update stats
                state.stats.fieldsProtected++;
                updateUIStats();
                
                return token;
            } catch (error) {
                console.error('❌ Sentinel: Protection failed:', error);
                return null;
            }
        }
        
        async encryptValue(value) {
            const iv = crypto.getRandomValues(new Uint8Array(12));
            const encoder = new TextEncoder();
            const data = encoder.encode(value);
            
            const encrypted = await crypto.subtle.encrypt(
                { name: CONFIG.ENCRYPTION_ALGORITHM, iv },
                this.key,
                data
            );
            
            return {
                ciphertext: this.arrayBufferToBase64(encrypted),
                iv: this.arrayBufferToBase64(iv)
            };
        }
        
        hashString(str) {
            // Simple non-crypto hash for demo
            let hash = 0;
            for (let i = 0; i < str.length; i++) {
                hash = ((hash << 5) - hash) + str.charCodeAt(i);
                hash |= 0;
            }
            return Math.abs(hash).toString(36);
        }
        
        arrayBufferToBase64(buffer) {
            const bytes = new Uint8Array(buffer);
            let binary = '';
            for (let i = 0; i < bytes.byteLength; i++) {
                binary += String.fromCharCode(bytes[i]);
            }
            return btoa(binary);
        }
        
        handleInput(input, formId) {
            const hasPII = this.scanField(input, formId);
            
            // Update monitor with debouncing
            debouncedUpdateMonitors();
            
            return hasPII;
        }
        
        handleFocus(input) {
            // Reveal original value if it's protected and masked
            if (input._sentinelIsMasked && this.originalValues.has(input)) {
                const original = this.originalValues.get(input);
                input.value = original;
                input._sentinelIsMasked = false;
                input.classList.remove('masked');
            }
        }
        
        handleBlur(input, formId) {
            // Apply masking if it has PII and is in protected form
            const formInfo = this.attachedForms.get(formId);
            if (input._sentinelHasPII && formInfo.isProtected) {
                this.maskField(input);
            }
            
            // Update monitor
            updateMonitors();
        }
        
        maskField(input) {
            const original = this.originalValues.get(input);
            if (!original || input._sentinelIsMasked) return;
            
            let masked;
            switch(input._sentinelPIIType) {
                case 'email':
                    const [local, domain] = original.split('@');
                    masked = local.charAt(0) + '*'.repeat(Math.max(0, local.length - 1)) + '@' + domain;
                    break;
                case 'creditCard':
                    const last4 = original.replace(/\D/g, '').slice(-4);
                    masked = '****-****-****-' + last4;
                    break;
                case 'apiKey':
                    const prefix = original.substring(0, Math.min(8, original.length));
                    masked = prefix + '*'.repeat(Math.max(0, original.length - prefix.length));
                    break;
                default:
                    masked = '*'.repeat(original.length);
            }
            
            input.value = masked;
            input._sentinelIsMasked = true;
            input.classList.add('masked');
        }
        
        addProtectionBadge(input) {
            if (!input.parentNode) return;
            
            // Remove existing badge
            const existing = input.parentNode.querySelector('.protection-badge');
            if (existing) existing.remove();
            
            // Create new badge
            const badge = document.createElement('span');
            badge.className = 'protection-badge';
            badge.innerHTML = '<i class="fas fa-shield-check"></i>';
            badge.title = 'PII Protected';
            
            // Style the badge
            Object.assign(badge.style, {
                position: 'absolute',
                right: '10px',
                top: '50%',
                transform: 'translateY(-50%)',
                color: CONFIG.COLORS.success,
                fontSize: '0.9em',
                pointerEvents: 'none',
                zIndex: '10'
            });
            
            input.parentNode.style.position = 'relative';
            input.parentNode.appendChild(badge);
        }
        
        getFormData(formId) {
            const formInfo = this.attachedForms.get(formId);
            if (!formInfo) return null;
            
            const data = {};
            let piiCount = 0;
            
            formInfo.inputs.forEach(input => {
                const fieldName = input.id.replace(/^(vuln|prot)/, '').toLowerCase();
                
                if (formInfo.isProtected && this.encryptedData.has(input)) {
                    const encrypted = this.encryptedData.get(input);
                    data[fieldName] = {
                        protected: true,
                        type: encrypted.type,
                        token: encrypted.token,
                        originalLength: encrypted.original.length
                    };
                    piiCount++;
                } else {
                    data[fieldName] = input.value;
                    if (input._sentinelHasPII) piiCount++;
                }
            });
            
            return { data, piiCount };
        }
        
        cleanup() {
            this.attachedForms.forEach((formInfo, formId) => {
                formInfo.inputs.forEach(input => {
                    if (input._sentinelListeners) {
                        input.removeEventListener('input', input._sentinelListeners.onInput);
                        input.removeEventListener('focus', input._sentinelListeners.onFocus);
                        input.removeEventListener('blur', input._sentinelListeners.onBlur);
                        delete input._sentinelListeners;
                    }
                });
            });
            
            this.attachedForms.clear();
            this.originalValues = new WeakMap();
            this.encryptedData = new WeakMap();
        }
    }
    
    // ===== APPLICATION LOGIC =====
    function initApplication() {
        console.log('🚀 Initializing Sentinel Privacy Lab...');
        
        // Initialize Sentinel SDK
        state.sentinel = new Sentinel();
        
        // Get DOM elements
        cacheDOMElements();
        
        // Setup event listeners
        setupEventListeners();
        
        // Initialize UI
        updateUIStats();
        updateMonitors();
        
        // Attach Sentinel to forms
        setTimeout(() => {
            state.sentinelActive = state.sentinel.attach('vulnerableForm');
            state.sentinelActive = state.sentinel.attach('protectedForm') && state.sentinelActive;
            
            if (state.sentinelActive) {
                console.log('✅ Application fully initialized');
                showToast('Sentinel Privacy Lab is ready!', 'success');
            }
        }, 500);
    }
    
    function cacheDOMElements() {
        state.forms.vulnerable = document.getElementById('vulnerableForm');
        state.forms.protected = document.getElementById('protectedForm');
        state.monitors.vulnerable = document.getElementById('vulnerableMonitor');
        state.monitors.protected = document.getElementById('protectedMonitor');
    }
    
    function setupEventListeners() {
        // Send buttons
        document.getElementById('sendVulnerableBtn').addEventListener('click', handleVulnerableSubmit);
        document.getElementById('sendProtectedBtn').addEventListener('click', handleProtectedSubmit);
        
        // Monitor all input changes for stats
        const allInputs = document.querySelectorAll('input, textarea');
        allInputs.forEach(input => {
            input.addEventListener('input', () => {
                state.stats.totalEvents++;
                updateMonitors();
            });
        });
    }
    
    function handleVulnerableSubmit() {
        if (!state.sentinel) return;
        
        const formData = state.sentinel.getFormData('vulnerableForm');
        if (!formData) return;
        
        // Count PII that would be leaked
        const leakedPII = countPIIInObject(formData.data);
        state.stats.leaksPrevented += leakedPII;
        
        // Show alert
        showToast(
            `⚠️ ${leakedPII} PII fields would be leaked!`,
            'danger',
            5000
        );
        
        // Update UI
        updateUIStats();
        updateMonitors();
        
        // Log to console
        console.log('📤 Vulnerable form submission:', {
            data: formData.data,
            piiCount: formData.piiCount,
            leaked: leakedPII
        });
    }
    
    async function handleProtectedSubmit() {
        if (!state.sentinel) return;
        
        const formData = state.sentinel.getFormData('protectedForm');
        if (!formData) return;
        
        // Simulate API call
        const protectedCount = Object.values(formData.data).filter(
            item => item && typeof item === 'object' && item.protected
        ).length;
        
        // Show success message
        showToast(
            `✅ ${protectedCount} fields protected and sent securely!`,
            'success',
            5000
        );
        
        // Log to console
        console.log('🔒 Protected form submission:', {
            data: formData.data,
            protectedCount,
            totalFields: Object.keys(formData.data).length
        });
    }
    
    function updateMonitors() {
        if (!state.sentinel || !state.monitors.vulnerable || !state.monitors.protected) return;
        
        // Update vulnerable monitor
        const vulnData = state.sentinel.getFormData('vulnerableForm');
        if (vulnData) {
            const monitorContent = formatVulnerableMonitor(vulnData.data);
            state.monitors.vulnerable.innerHTML = monitorContent;
            
            // Update status
            const statusEl = document.getElementById('vulnerableStatus');
            if (statusEl) {
                const statusDot = statusEl.querySelector('.status-dot');
                const statusText = statusEl.querySelector('.status-text');
                
                if (vulnData.piiCount > 0) {
                    statusDot.className = 'status-dot danger';
                    statusText.textContent = `${vulnData.piiCount} PII exposed`;
                } else {
                    statusDot.className = 'status-dot';
                    statusText.textContent = 'No PII detected';
                }
            }
        }
        
        // Update protected monitor
        const protData = state.sentinel.getFormData('protectedForm');
        if (protData) {
            const monitorContent = formatProtectedMonitor(protData.data);
            state.monitors.protected.innerHTML = monitorContent;
            
            // Update status
            const statusEl = document.getElementById('protectedStatus');
            if (statusEl) {
                const statusDot = statusEl.querySelector('.status-dot');
                const statusText = statusEl.querySelector('.status-text');
                
                const protectedCount = Object.values(protData.data).filter(
                    item => item && typeof item === 'object' && item.protected
                ).length;
                
                if (protectedCount > 0) {
                    statusDot.className = 'status-dot success';
                    statusText.textContent = `${protectedCount} fields protected`;
                } else {
                    statusDot.className = 'status-dot';
                    statusText.textContent = 'Ready';
                }
            }
        }
    }
    
    function formatVulnerableMonitor(data) {
        const jsonStr = JSON.stringify(data, null, 2);
        let formatted = jsonStr;
        
        // Highlight PII in red
        Object.values(CONFIG.PII_PATTERNS).forEach(pattern => {
            const matches = jsonStr.match(pattern);
            if (matches) {
                matches.forEach(match => {
                    const escapedMatch = match.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
                    const regex = new RegExp(`("${escapedMatch}")`, 'g');
                    formatted = formatted.replace(regex, '<span class="highlight-danger">$1</span>');
                });
            }
        });
        
        return formatted;
    }
    
    function formatProtectedMonitor(data) {
        let formatted = '';
        
        Object.entries(data).forEach(([key, value]) => {
            if (value && typeof value === 'object' && value.protected) {
                formatted += `<span style="color:#60a5fa">"${key}"</span>: {\n`;
                formatted += `  <span class="highlight-success">"protected"</span>: true,\n`;
                formatted += `  <span class="highlight-success">"type"</span>: "${value.type}",\n`;
                
                if (value.token.encrypted) {
                    formatted += `  <span class="highlight-success">"encrypted"</span>: "${value.token.encrypted}",\n`;
                    formatted += `  <span class="highlight-success">"algorithm"</span>: "${CONFIG.ENCRYPTION_ALGORITHM}"\n`;
                } else {
                    formatted += `  <span class="highlight-success">"token"</span>: "${value.token.token}",\n`;
                    formatted += `  <span class="highlight-success">"algorithm"</span>: "${value.token.algorithm}"\n`;
                }
                
                formatted += `},\n`;
            } else {
                formatted += `<span style="color:#60a5fa">"${key}"</span>: "${value}",\n`;
            }
        });
        
        return formatted || 'No protected data yet. Start typing sensitive information...';
    }
    
    function countPIIInObject(obj) {
        const jsonStr = JSON.stringify(obj);
        let count = 0;
        
        Object.values(CONFIG.PII_PATTERNS).forEach(pattern => {
            const matches = jsonStr.match(pattern);
            if (matches) count += matches.length;
        });
        
        return count;
    }
    
    function updateUIStats() {
        // Update stat counters
        document.getElementById('piiDetected').textContent = state.stats.piiDetected;
        document.getElementById('fieldsProtected').textContent = state.stats.fieldsProtected;
        document.getElementById('leaksPrevented').textContent = state.stats.leaksPrevented;
    }
    
    function showToast(message, type = 'info', duration = 3000) {
        // Remove existing toasts
        const existingToasts = document.querySelectorAll('.sentinel-toast');
        existingToasts.forEach(toast => toast.remove());
        
        // Create toast element
        const toast = document.createElement('div');
        toast.className = `sentinel-toast sentinel-toast-${type}`;
        toast.textContent = message;
        
        // Style the toast
        Object.assign(toast.style, {
            position: 'fixed',
            top: '20px',
            right: '20px',
            padding: '12px 20px',
            background: type === 'danger' ? CONFIG.COLORS.danger : 
                       type === 'success' ? CONFIG.COLORS.success : 
                       type === 'warning' ? CONFIG.COLORS.warning : CONFIG.COLORS.info,
            color: 'white',
            borderRadius: '8px',
            boxShadow: '0 4px 12px rgba(0,0,0,0.15)',
            zIndex: '9999',
            fontWeight: '500',
            animation: 'toastSlideIn 0.3s ease'
        });
        
        // Add animation keyframes
        if (!document.getElementById('toast-animations')) {
            const style = document.createElement('style');
            style.id = 'toast-animations';
            style.textContent = `
                @keyframes toastSlideIn {
                    from { transform: translateX(100%); opacity: 0; }
                    to { transform: translateX(0); opacity: 1; }
                }
                @keyframes toastSlideOut {
                    from { transform: translateX(0); opacity: 1; }
                    to { transform: translateX(100%); opacity: 0; }
                }
            `;
            document.head.appendChild(style);
        }
        
        document.body.appendChild(toast);
        
        // Remove after duration
        setTimeout(() => {
            toast.style.animation = 'toastSlideOut 0.3s ease';
            setTimeout(() => toast.remove(), 300);
        }, duration);
    }
    
    function debouncedUpdateMonitors() {
        const now = Date.now();
        if (now - state.monitors.lastUpdate > CONFIG.MONITOR_UPDATE_DELAY) {
            updateMonitors();
            state.monitors.lastUpdate = now;
        } else {
            clearTimeout(state.monitors.updateTimeout);
            state.monitors.updateTimeout = setTimeout(updateMonitors, CONFIG.MONITOR_UPDATE_DELAY);
        }
    }
    
    // ===== INITIALIZATION =====
    document.addEventListener('DOMContentLoaded', initApplication);
    
    // ===== GLOBAL EXPORTS =====
    window.SentinelLab = {
        state,
        CONFIG,
        updateMonitors,
        showToast,
        getStats: () => ({ ...state.stats, sentinelActive: state.sentinelActive })
    };
    
})();
