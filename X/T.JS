// Screenpipe - Healthcare Screen Capture & Activity Tracking
// Main application code for doctor/admin panel and telehealth integration

class Screenpipe {
    constructor(options = {}) {
      this.options = {
        autoStart: false,
        captureInterval: 5000, // milliseconds between captures
        activityTrackingEnabled: true,
        screenCaptureEnabled: true,
        privacyMode: false,
        patientConsentRequired: true,
        storageLocation: 'cloud', // 'local' or 'cloud'
        encryptData: true,
        maxScreenCaptures: 500, // Limit the number of captures to prevent memory issues
        ...options
      };
      
      this.state = {
        isRecording: false,
        hasPatientConsent: false,
        currentSessionId: null,
        currentConsultationStartTime: null,
        activityLog: [],
        screenCaptures: [],
        privacyZones: [], // Areas to blur/exclude from capture
        consultationMetrics: {
          totalDuration: 0,
          activeInputTime: 0,
          screenTimeByApplication: {},
        }
      };
      
      this.captureInterval = null;
      this.activityTracker = null;
      this.lastMouseMove = null;
      this.screenStream = null;
      this.videoElement = null;
      
      // Bind methods
      this.startRecording = this.startRecording.bind(this);
      this.stopRecording = this.stopRecording.bind(this);
      this.captureScreen = this.captureScreen.bind(this);
      this.trackActivity = this.trackActivity.bind(this);
      this.trackTouchActivity = this.trackTouchActivity.bind(this);
      this.setPatientConsent = this.setPatientConsent.bind(this);
      this.addPrivacyZone = this.addPrivacyZone.bind(this);
      this.generateReport = this.generateReport.bind(this);
      this.savePrivacyZones = this.savePrivacyZones.bind(this);
      this.loadPrivacyZones = this.loadPrivacyZones.bind(this);
      
      // Initialize if autoStart
      if (this.options.autoStart) {
        this.init();
      }
    }
    
    async init() {
      try {
        // Setup event listeners
        document.addEventListener('keydown', this.trackActivity);
        document.addEventListener('mousemove', this.trackActivity);
        document.addEventListener('click', this.trackActivity);
        
        // Add touch event support for mobile devices
        document.addEventListener('touchstart', this.trackTouchActivity);
        document.addEventListener('touchmove', this.trackTouchActivity);
        document.addEventListener('touchend', this.trackTouchActivity);
        
        // Load saved privacy zones if any
        await this.loadPrivacyZones();
        
        // Check for necessary permissions
        if (this.options.screenCaptureEnabled) {
          const permissionResult = await this.requestScreenCapturePermission();
          if (!permissionResult) {
            console.warn('Screen capture permission denied. Some features will be limited.');
          }
        }
        
        console.log('Screenpipe initialized successfully');
        return true;
      } catch (error) {
        console.error('Failed to initialize Screenpipe:', error);
        return false;
      }
    }
    
    async requestScreenCapturePermission() {
      try {
        // Request screen capture permission
        const stream = await navigator.mediaDevices.getDisplayMedia({
          video: { cursor: "always" },
          audio: false
        });
        
        // Store the stream for later use
        this.screenStream = stream;
        
        // Set up video element (hidden by default)
        this.videoElement = document.createElement('video');
        this.videoElement.srcObject = stream;
        this.videoElement.style.display = 'none';
        document.body.appendChild(this.videoElement);
        
        // Handle stream ending (user cancels)
        stream.getVideoTracks()[0].addEventListener('ended', () => {
          console.log('Screen sharing ended by user');
          if (this.state.isRecording) {
            this.stopRecording();
          }
          this.cleanupVideoElement();
        });
        
        await this.videoElement.play();
        
        return true;
      } catch (error) {
        console.error('Screen capture permission denied:', error);
        return false;
      }
    }
    
    cleanupVideoElement() {
      if (this.videoElement) {
        this.videoElement.pause();
        this.videoElement.srcObject = null;
        document.body.removeChild(this.videoElement);
        this.videoElement = null;
      }
      
      if (this.screenStream) {
        this.screenStream.getTracks().forEach(track => track.stop());
        this.screenStream = null;
      }
    }
    
    async startRecording(consultationId = null) {
      if (!this.options.patientConsentRequired || this.state.hasPatientConsent) {
        // Re-request screen capture if needed
        if (this.options.screenCaptureEnabled && !this.screenStream) {
          const permissionResult = await this.requestScreenCapturePermission();
          if (!permissionResult) {
            console.warn('Screen capture permission denied. Cannot start recording.');
            return false;
          }
        }
        
        // Generate session ID if not provided
        this.state.currentSessionId = consultationId || `session_${Date.now()}`;
        this.state.currentConsultationStartTime = Date.now();
        this.state.isRecording = true;
        
        // Reset metrics for new session
        this.state.consultationMetrics = {
          totalDuration: 0,
          activeInputTime: 0,
          screenTimeByApplication: {},
        };
        
        // Clear previous captures
        this.state.screenCaptures = [];
        
        // Start screen capture interval
        if (this.options.screenCaptureEnabled && this.screenStream) {
          this.captureInterval = setInterval(this.captureScreen, this.options.captureInterval);
        }
        
        // Start activity tracking
        if (this.options.activityTrackingEnabled) {
          this.trackActivityStart();
        }
        
        console.log(`Recording started for session: ${this.state.currentSessionId}`);
        return true;
      } else {
        console.warn('Cannot start recording: Patient consent required');
        return false;
      }
    }
    
    stopRecording() {
      if (!this.state.isRecording) {
        console.warn('No active recording to stop');
        return null;
      }
      
      // Stop intervals
      clearInterval(this.captureInterval);
      this.captureInterval = null;
      
      // Calculate final metrics
      if (this.state.currentConsultationStartTime) {
        const endTime = Date.now();
        const sessionDuration = endTime - this.state.currentConsultationStartTime;
        this.state.consultationMetrics.totalDuration = sessionDuration;
      }
      
      // Compile final data
      const sessionData = {
        id: this.state.currentSessionId,
        startTime: this.state.currentConsultationStartTime,
        endTime: Date.now(),
        duration: this.state.consultationMetrics.totalDuration,
        activeInputTime: this.state.consultationMetrics.activeInputTime,
        captureCount: this.state.screenCaptures.length,
        metrics: this.state.consultationMetrics
      };
      
      // Reset state
      this.state.isRecording = false;
      
      // Save data if needed
      if (this.options.storageLocation === 'cloud') {
        this.saveToCloud(sessionData)
          .catch(error => console.error('Error saving session data to cloud:', error));
      }
      
      console.log('Recording stopped and data compiled');
      return sessionData;
    }
    
    async captureScreen() {
      if (!this.state.isRecording || !this.screenStream || !this.videoElement) return;
      
      try {
        // Manage capture limits to prevent memory issues
        if (this.state.screenCaptures.length >= this.options.maxScreenCaptures) {
          console.warn(`Maximum screen captures (${this.options.maxScreenCaptures}) reached, removing oldest capture`);
          this.state.screenCaptures.shift(); // Remove oldest capture
        }
        
        // Create canvas for capture
        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('2d');
        
        // Set dimensions from video stream
        canvas.width = this.videoElement.videoWidth;
        canvas.height = this.videoElement.videoHeight;
        
        // Draw video frame to canvas
        ctx.drawImage(this.videoElement, 0, 0, canvas.width, canvas.height);
        
        // Apply privacy zones if enabled
        if (this.options.privacyMode && this.state.privacyZones.length > 0) {
          this.state.privacyZones.forEach(zone => {
            // Convert percentages to actual pixels if stored that way
            const x = zone.isPercentage ? (zone.x * canvas.width) / 100 : zone.x;
            const y = zone.isPercentage ? (zone.y * canvas.height) / 100 : zone.y;
            const width = zone.isPercentage ? (zone.width * canvas.width) / 100 : zone.width;
            const height = zone.isPercentage ? (zone.height * canvas.height) / 100 : zone.height;
            
            ctx.fillStyle = 'rgba(0, 0, 0, 1)';
            ctx.fillRect(x, y, width, height);
          });
        }
        
        // Convert to image data (with lower quality for storage efficiency)
        const imageData = canvas.toDataURL('image/jpeg', 0.7);
        
        // Get current application focus
        const activeApplication = this.getCurrentApplicationFocus();
        
        // Store capture data
        const captureData = {
          timestamp: Date.now(),
          sessionId: this.state.currentSessionId,
          imageData: this.options.encryptData ? this.encryptData(imageData) : imageData,
          activeApplication
        };
        
        this.state.screenCaptures.push(captureData);
        
        // Tracking application focus time
        if (!this.state.consultationMetrics.screenTimeByApplication[activeApplication]) {
          this.state.consultationMetrics.screenTimeByApplication[activeApplication] = 0;
        }
        this.state.consultationMetrics.screenTimeByApplication[activeApplication] += this.options.captureInterval / 1000;
        
        // Cleanup
        canvas.remove();
        
        return captureData;
      } catch (error) {
        console.error('Error capturing screen:', error);
        return null;
      }
    }
    
    trackActivity(event) {
      if (!this.state.isRecording || !this.options.activityTrackingEnabled) return;
      
      const timestamp = Date.now();
      const activityType = event.type;
      let activityData = {
        timestamp,
        type: activityType,
        sessionId: this.state.currentSessionId
      };
      
      // Add specific data based on activity type
      switch (activityType) {
        case 'keydown':
          // Don't log actual keys for privacy, just the fact keypresses happened
          activityData.isKeypress = true;
          this.state.consultationMetrics.activeInputTime += 200; // Approximate time for keypress
          break;
        case 'mousemove':
          // Throttle mouse movements to prevent excessive logging
          if (this.lastMouseMove && timestamp - this.lastMouseMove < 500) return;
          this.lastMouseMove = timestamp;
          activityData.position = { x: event.clientX, y: event.clientY };
          break;
        case 'click':
          activityData.position = { x: event.clientX, y: event.clientY };
          activityData.target = event.target.tagName;
          this.state.consultationMetrics.activeInputTime += 100; // Approximate time for click
          break;
      }
      
      this.state.activityLog.push(activityData);
      
      // Keep activity log size manageable
      if (this.state.activityLog.length > 1000) {
        this.state.activityLog = this.state.activityLog.slice(-1000);
      }
    }
    
    trackTouchActivity(event) {
      if (!this.state.isRecording || !this.options.activityTrackingEnabled) return;
      
      const timestamp = Date.now();
      const activityType = event.type;
      let activityData = {
        timestamp,
        type: activityType,
        sessionId: this.state.currentSessionId
      };
      
      // Add specific data based on touch activity type
      switch (activityType) {
        case 'touchstart':
          activityData.touchPoints = event.touches.length;
          this.state.consultationMetrics.activeInputTime += 100; // Approximate time for touch
          break;
        case 'touchmove':
          // Throttle touch movements to prevent excessive logging
          if (this.lastTouchMove && timestamp - this.lastTouchMove < 500) return;
          this.lastTouchMove = timestamp;
          break;
        case 'touchend':
          activityData.touchDuration = timestamp - (this.lastTouchStart || timestamp);
          break;
      }
      
      if (activityType === 'touchstart') {
        this.lastTouchStart = timestamp;
      }
      
      this.state.activityLog.push(activityData);
      
      // Keep activity log size manageable
      if (this.state.activityLog.length > 1000) {
        this.state.activityLog = this.state.activityLog.slice(-1000);
      }
    }
    
    trackActivityStart() {
      this.activityStartTime = Date.now();
      // Additional activity tracking logic here
    }
    
    getCurrentApplicationFocus() {
      // In browser environment, return the active tab/window info
      // This is a simplification - actual implementation would use platform-specific APIs
      return document.title || 'Healthcare Platform';
    }
    
    setPatientConsent(hasConsent) {
      this.state.hasPatientConsent = hasConsent;
      return hasConsent;
    }
    
    addPrivacyZone(zone) {
      // Validate zone properties
      if (!zone || typeof zone.x !== 'number' || typeof zone.y !== 'number' || 
          typeof zone.width !== 'number' || typeof zone.height !== 'number') {
        console.error('Invalid privacy zone format', zone);
        return false;
      }
      
      // Store whether coordinates are percentages or absolute
      const isPercentage = zone.isPercentage || false;
      
      // Add zone with percentage indicator
      this.state.privacyZones.push({
        ...zone,
        isPercentage
      });
      
      // Save privacy zones to persistent storage
      this.savePrivacyZones();
      
      return this.state.privacyZones.length;
    }
    
    removePrivacyZone(index) {
      if (index >= 0 && index < this.state.privacyZones.length) {
        this.state.privacyZones.splice(index, 1);
        this.savePrivacyZones();
        return true;
      }
      return false;
    }
    
    savePrivacyZones() {
      try {
        localStorage.setItem('screenpipe_privacy_zones', JSON.stringify(this.state.privacyZones));
      } catch (error) {
        console.error('Failed to save privacy zones:', error);
      }
    }
    
    loadPrivacyZones() {
      try {
        const savedZones = localStorage.getItem('screenpipe_privacy_zones');
        if (savedZones) {
          this.state.privacyZones = JSON.parse(savedZones);
        }
      } catch (error) {
        console.error('Failed to load privacy zones:', error);
      }
    }
    
    encryptData(data) {
      // This is a placeholder for actual encryption that should be implemented
      // In production, use a proper encryption library or service
      if (!this.options.encryptData) return data;
      
      try {
        // For demo purposes, we'll just indicate that the data would be encrypted
        // In real implementation, use SubtleCrypto API or a dedicated encryption library
        const encryptionPrefix = 'ENCRYPTED:';
        if (data.startsWith(encryptionPrefix)) return data; // Already encrypted
        
        // In production, replace with actual encryption code
        // This is just a placeholder to show it would be encrypted
        return `${encryptionPrefix}${data.substring(0, 20)}...`;
      } catch (error) {
        console.error('Encryption failed:', error);
        return data; // Return original data if encryption fails
      }
    }
    
    decryptData(encryptedData) {
      // Placeholder for actual decryption logic
      // In production, use the corresponding decryption method for your encryption
      const encryptionPrefix = 'ENCRYPTED:';
      if (!encryptedData || !encryptedData.startsWith(encryptionPrefix)) {
        return encryptedData; // Not encrypted or invalid data
      }
      
      // In production, replace with actual decryption code
      // This is just a placeholder
      return 'Decrypted content would appear here';
    }
    
    generateReport() {
      if (!this.state.currentSessionId) {
        console.warn('No active session to generate report from');
        return null;
      }
      
      const report = {
        sessionId: this.state.currentSessionId,
        doctorId: this.options.doctorId || 'unknown',
        patientId: this.options.patientId || 'unknown',
        metrics: {
          totalDuration: this.formatDuration(this.state.consultationMetrics.totalDuration),
          activeInputTime: this.formatDuration(this.state.consultationMetrics.activeInputTime),
          inputEfficiency: Math.round((this.state.consultationMetrics.activeInputTime / this.state.consultationMetrics.totalDuration) * 100) + '%',
          screenTimeBreakdown: this.state.consultationMetrics.screenTimeByApplication,
          captureCount: this.state.screenCaptures.length
        },
        timestamp: Date.now(),
        summary: this.generateActivitySummary()
      };
      
      return report;
    }
    
    formatDuration(ms) {
      const seconds = Math.floor(ms / 1000);
      const minutes = Math.floor(seconds / 60);
      const hours = Math.floor(minutes / 60);
      
      return `${hours}h ${minutes % 60}m ${seconds % 60}s`;
    }
    
    generateActivitySummary() {
      // Analyze activity patterns and generate insights
      return {
        mostActiveApplication: this.getMostUsedApplication(),
        inputFrequency: this.calculateInputFrequency(),
        efficiencyScore: this.calculateEfficiencyScore()
      };
    }
    
    getMostUsedApplication() {
      const apps = this.state.consultationMetrics.screenTimeByApplication;
      let maxTime = 0;
      let maxApp = 'None';
      
      for (const app in apps) {
        if (apps[app] > maxTime) {
          maxTime = apps[app];
          maxApp = app;
        }
      }
      
      return { name: maxApp, timeSpent: this.formatDuration(maxTime * 1000) };
    }
    
    calculateInputFrequency() {
      if (!this.state.activityLog.length) return 'No activity data';
      
      const keyPresses = this.state.activityLog.filter(a => a.type === 'keydown').length;
      const touchEvents = this.state.activityLog.filter(a => a.type === 'touchstart').length;
      const totalInputs = keyPresses + touchEvents;
      
      const durationMinutes = this.state.consultationMetrics.totalDuration / 60000;
      if (durationMinutes === 0) return '0 inputs/minute';
      
      const inputsPerMinute = (totalInputs / durationMinutes).toFixed(1);
      return `${inputsPerMinute} inputs/minute`;
    }
    
    calculateEfficiencyScore() {
      // If no duration recorded, avoid division by zero
      if (!this.state.consultationMetrics.totalDuration) return 'N/A';
      
      // Simple algorithm to rate productivity
      const activePct = (this.state.consultationMetrics.activeInputTime / this.state.consultationMetrics.totalDuration);
      
      if (activePct > 0.8) return 'Excellent';
      if (activePct > 0.6) return 'Good';
      if (activePct > 0.4) return 'Average';
      return 'Below Average';
    }
    
    async saveToCloud(data) {
      try {
        // Placeholder for API call to save data
        console.log('Saving session data to cloud storage', data.id);
        // In real implementation, would make API call to backend
        
        // Simulate API call with promise
        await new Promise(resolve => setTimeout(resolve, 300));
        
        return true;
      } catch (error) {
        console.error('Failed to save data to cloud:', error);
        // Consider implementing a retry mechanism or local fallback storage
        return false;
      }
    }
    
    dispose() {
      // First stop any active recording
      if (this.state.isRecording) {
        this.stopRecording();
      }
      
      // Clean up media resources
      this.cleanupVideoElement();
      
      // Remove event listeners
      document.removeEventListener('keydown', this.trackActivity);
      document.removeEventListener('mousemove', this.trackActivity);
      document.removeEventListener('click', this.trackActivity);
      document.removeEventListener('touchstart', this.trackTouchActivity);
      document.removeEventListener('touchmove', this.trackTouchActivity);
      document.removeEventListener('touchend', this.trackTouchActivity);
      
      // Clear intervals
      clearInterval(this.captureInterval);
      
      // Clear state
      this.state.activityLog = [];
      this.state.screenCaptures = [];
      
      console.log('Screenpipe resources cleaned up');
      return true;
    }
  }
  
  // UI Components for Doctor/Admin Panel
  class ScreenpipeUI {
    constructor(screenpipeInstance, containerId = 'screenpipe-container') {
      this.screenpipe = screenpipeInstance;
      this.container = document.getElementById(containerId) || this.createContainer(containerId);
      this.metricsUpdateInterval = null;
      this.privacySelectionActive = false;
      
      this.init();
    }
    
    createContainer(id) {
      const div = document.createElement('div');
      div.id = id;
      document.body.appendChild(div);
      return div;
    }
    
    init() {
      this.render();
      this.attachEventListeners();
    }
    
    render() {
      this.container.innerHTML = `
        <div class="screenpipe-controls">
          <h3>Screenpipe Productivity Tools</h3>
          
          <div class="consent-section">
            <label>
              <input type="checkbox" id="patient-consent-checkbox"> 
              Patient has provided consent for screen recording
            </label>
          </div>
          
          <div class="control-buttons">
            <button id="start-recording" class="btn btn-primary" disabled>
              Start Recording
            </button>
            <button id="stop-recording" class="btn btn-danger" disabled>
              Stop Recording
            </button>
            <button id="generate-report" class="btn btn-info" disabled>
              Generate Report
            </button>
          </div>
          
          <div class="privacy-controls">
            <h4>Privacy Controls</h4>
            <label>
              <input type="checkbox" id="privacy-mode-checkbox"> 
              Enable Privacy Mode
            </label>
            <button id="add-privacy-zone" class="btn btn-secondary">
              Add Privacy Zone
            </button>
            <button id="view-privacy-zones" class="btn btn-secondary">
              View Privacy Zones
            </button>
          </div>
          
          <div class="status-indicator">
            Status: <span id="recording-status">Not Recording</span>
          </div>
        </div>
        
        <div class="metrics-panel" id="metrics-panel">
          <h4>Current Session Metrics</h4>
          <div id="live-metrics">
            <p>No active session</p>
          </div>
        </div>
        
        <div id="privacy-zones-panel" class="privacy-zones-panel" style="display: none;">
          <h4>Configured Privacy Zones</h4>
          <div id="privacy-zones-list"></div>
        </div>
        
        <div id="report-output" class="report-output"></div>
      `;
    }
    
    attachEventListeners() {
      // Consent checkbox
      const consentCheckbox = document.getElementById('patient-consent-checkbox');
      consentCheckbox.addEventListener('change', (e) => {
        this.screenpipe.setPatientConsent(e.target.checked);
        document.getElementById('start-recording').disabled = !e.target.checked;
      });
      
      // Privacy mode toggle
      const privacyModeCheckbox = document.getElementById('privacy-mode-checkbox');
      privacyModeCheckbox.addEventListener('change', (e) => {
        this.screenpipe.options.privacyMode = e.target.checked;
      });
      
      // Start recording button
      const startBtn = document.getElementById('start-recording');
      startBtn.addEventListener('click', async () => {
        const result = await this.screenpipe.startRecording();
        if (result) {
          this.updateUI({ isRecording: true });
        } else {
          alert('Failed to start recording. Please check permissions and try again.');
        }
      });
      
      // Stop recording button
      const stopBtn = document.getElementById('stop-recording');
      stopBtn.addEventListener('click', () => {
        const sessionData = this.screenpipe.stopRecording();
        this.updateUI({ isRecording: false });
        if (sessionData) {
          this.displaySessionSummary(sessionData);
        }
      });
      
      // Generate report button
      const reportBtn = document.getElementById('generate-report');
      reportBtn.addEventListener('click', () => {
        const report = this.screenpipe.generateReport();
        if (report) {
          this.displayReport(report);
        } else {
          alert('Could not generate report. No active session data available.');
        }
      });
      
      // Add privacy zone button
      const privacyZoneBtn = document.getElementById('add-privacy-zone');
      privacyZoneBtn.addEventListener('click', () => {
        if (!this.privacySelectionActive) {
          this.startPrivacyZoneSelection();
        }
      });
      
      // View privacy zones button
      const viewPrivacyZonesBtn = document.getElementById('view-privacy-zones');
      viewPrivacyZonesBtn.addEventListener('click', () => {
        this.togglePrivacyZonesPanel();
      });
    }
    
    updateUI(state) {
      const statusEl = document.getElementById('recording-status');
      const startBtn = document.getElementById('start-recording');
      const stopBtn = document.getElementById('stop-recording');
      const reportBtn = document.getElementById('generate-report');
      const metricsPanel = document.getElementById('live-metrics');
      
      if (state.isRecording) {
        statusEl.textContent = 'Recording';
        statusEl.className = 'recording';
        startBtn.disabled = true;
        stopBtn.disabled = false;
        reportBtn.disabled = false;
        
        // Start metrics updates
        this.metricsUpdateInterval = setInterval(() => {
          this.updateLiveMetrics();
        }, 1000);
      } else {
        statusEl.textContent = 'Not Recording';
        statusEl.className = '';
        startBtn.disabled = !this.screenpipe.state.hasPatientConsent;
        stopBtn.disabled = true;
        reportBtn.disabled = !this.screenpipe.state.currentSessionId;
        
        // Stop metrics updates
        clearInterval(this.metricsUpdateInterval);
      }
    }
    
    updateLiveMetrics() {
      if (!this.screenpipe.state.isRecording) return;
      
      const metrics = document.getElementById('live-metrics');
      const currentDuration = Date.now() - this.screenpipe.state.currentConsultationStartTime;
      
      metrics.innerHTML = `
        <p><strong>Session ID:</strong> ${this.screenpipe.state.currentSessionId}</p>
        <p><strong>Duration:</strong> ${this.screenpipe.formatDuration(currentDuration)}</p>
        <p><strong>Active Input Time:</strong> ${this.screenpipe.formatDuration(this.screenpipe.state.consultationMetrics.activeInputTime)}</p>
        <p><strong>Screen Captures:</strong> ${this.screenpipe.state.screenCaptures.length}</p>
        <p><strong>Current Efficiency:</strong> ${Math.round((this.screenpipe.state.consultationMetrics.activeInputTime / currentDuration) * 100)}%</p>
      `;
    }
    
    displaySessionSummary(sessionData) {
      // Display quick session summary after stopping
      const reportOutput = document.getElementById('report-output');
      
      reportOutput.innerHTML = `
        <div class="session-summary">
          <h4>Session Complete</h4>
          <p><strong>Duration:</strong> ${this.screenpipe.formatDuration(sessionData.duration)}</p>
          <p><strong>Active Input Time:</strong> ${this.screenpipe.formatDuration(sessionData.activeInputTime)}</p>
          <p><strong>Captures:</strong> ${sessionData.captureCount}</p>
          <p><strong>Efficiency:</strong> ${Math.round((sessionData.activeInputTime / sessionData.duration) * 100)}%</p>
          <p>Click "Generate Report" for detailed analysis</p>
        </div>
      `;
    }
    
    displayReport(report) {
      if (!report) return;
      
      const reportOutput = document.getElementById('report-output');
      
      let appTimeHTML = '';
      for (const app in report.metrics.screenTimeBreakdown) {
        appTimeHTML += `
          <tr>
            <td>${app}</td>
            <td>${this.screenpipe.formatDuration(report.metrics.screenTimeBreakdown[app] * 1000)}</td>
          </tr>
        `;
      }
      
      reportOutput.innerHTML = `
        <div class="full-report">
          <h3>Consultation Report</h3>
          <p><strong>Session:</strong> ${report.sessionId}</p>
          <p><strong>Doctor ID:</strong> ${report.doctorId}</p>
          <p><strong>Patient ID:</strong> ${report.patientId}</p>
          <p><strong>Date:</strong> ${new Date(report.timestamp).toLocaleString()}</p>
          
<div class="metrics-section">
          <h4>Activity Metrics</h4>
          <table class="metrics-table">
            <tr>
              <td>Total Duration:</td>
              <td>${report.metrics.totalDuration}</td>
            </tr>
            <tr>
              <td>Active Input Time:</td>
              <td>${report.metrics.activeInputTime}</td>
            </tr>
            <tr>
              <td>Input Efficiency:</td>
              <td>${report.metrics.inputEfficiency}</td>
            </tr>
            <tr>
              <td>Efficiency Score:</td>
              <td>${report.summary.efficiencyScore}</td>
            </tr>
            <tr>
              <td>Input Frequency:</td>
              <td>${report.summary.inputFrequency}</td>
            </tr>
          </table>
          
          <h4>Application Usage</h4>
          <table class="app-usage-table">
            <thead>
              <tr>
                <th>Application</th>
                <th>Time Spent</th>
              </tr>
            </thead>
            <tbody>
              ${appTimeHTML}
            </tbody>
          </table>
          
          <p><strong>Most Used Application:</strong> ${report.summary.mostActiveApplication.name} (${report.summary.mostActiveApplication.timeSpent})</p>
        </div>
        
        <div class="actions">
          <button class="btn btn-primary" id="export-report">Export Report (PDF)</button>
          <button class="btn btn-secondary" id="share-report">Share with Healthcare Team</button>
        </div>
      </div>
    `;
    
    // Add event listeners for the report buttons
    document.getElementById('export-report').addEventListener('click', () => {
      this.exportReportAsPDF(report);
    });
    
    document.getElementById('share-report').addEventListener('click', () => {
      this.shareReport(report);
    });
  }
  
  exportReportAsPDF(report) {
    // This would use a PDF generation library in production
    console.log('Exporting report as PDF:', report.sessionId);
    alert('PDF Export feature would generate a downloadable report in production');
    // In production implementation, use a library like jsPDF or call a backend API
  }
  
  shareReport(report) {
    // Placeholder for sharing functionality
    console.log('Sharing report with healthcare team:', report.sessionId);
    
    // In a real implementation, would open a modal with sharing options
    const shareOptions = ['Email to team', 'Add to patient record', 'Send to referring physician'];
    
    alert(`In production, this would open sharing options:\n- ${shareOptions.join('\n- ')}`);
  }
  
  startPrivacyZoneSelection() {
    this.privacySelectionActive = true;
    
    // Create overlay for selection
    const overlay = document.createElement('div');
    overlay.className = 'privacy-selection-overlay';
    overlay.style.position = 'fixed';
    overlay.style.top = '0';
    overlay.style.left = '0';
    overlay.style.width = '100%';
    overlay.style.height = '100%';
    overlay.style.backgroundColor = 'rgba(0, 0, 0, 0.3)';
    overlay.style.zIndex = '9999';
    overlay.style.cursor = 'crosshair';
    
    document.body.appendChild(overlay);
    
    // Instructions
    const instructions = document.createElement('div');
    instructions.className = 'selection-instructions';
    instructions.style.position = 'fixed';
    instructions.style.top = '10px';
    instructions.style.left = '50%';
    instructions.style.transform = 'translateX(-50%)';
    instructions.style.padding = '10px';
    instructions.style.backgroundColor = '#fff';
    instructions.style.boxShadow = '0 0 10px rgba(0,0,0,0.3)';
    instructions.style.zIndex = '10000';
    instructions.innerHTML = '<b>Click and drag to select a privacy zone. Press ESC to cancel.</b>';
    
    document.body.appendChild(instructions);
    
    // Variables for selection
    let isSelecting = false;
    let startX, startY, endX, endY;
    let selectionBox = null;
    
    // Event listeners for selection
    overlay.addEventListener('mousedown', (e) => {
      isSelecting = true;
      startX = e.clientX;
      startY = e.clientY;
      
      // Create selection box
      selectionBox = document.createElement('div');
      selectionBox.className = 'selection-box';
      selectionBox.style.position = 'fixed';
      selectionBox.style.border = '2px dashed red';
      selectionBox.style.backgroundColor = 'rgba(255, 0, 0, 0.2)';
      selectionBox.style.zIndex = '10000';
      
      document.body.appendChild(selectionBox);
    });
    
    overlay.addEventListener('mousemove', (e) => {
      if (!isSelecting || !selectionBox) return;
      
      endX = e.clientX;
      endY = e.clientY;
      
      // Calculate rectangle dimensions
      const left = Math.min(startX, endX);
      const top = Math.min(startY, endY);
      const width = Math.abs(endX - startX);
      const height = Math.abs(endY - startY);
      
      // Update selection box
      selectionBox.style.left = left + 'px';
      selectionBox.style.top = top + 'px';
      selectionBox.style.width = width + 'px';
      selectionBox.style.height = height + 'px';
    });
    
    overlay.addEventListener('mouseup', (e) => {
      if (!isSelecting) return;
      
      isSelecting = false;
      endX = e.clientX;
      endY = e.clientY;
      
      // Calculate final dimensions
      const left = Math.min(startX, endX);
      const top = Math.min(startY, endY);
      const width = Math.abs(endX - startX);
      const height = Math.abs(endY - startY);
      
      // Only add if selection has some size
      if (width > 10 && height > 10) {
        // Convert to percentages for responsive privacy zones
        const viewportWidth = window.innerWidth;
        const viewportHeight = window.innerHeight;
        
        const zone = {
          x: (left / viewportWidth) * 100,
          y: (top / viewportHeight) * 100,
          width: (width / viewportWidth) * 100,
          height: (height / viewportHeight) * 100,
          isPercentage: true
        };
        
        this.screenpipe.addPrivacyZone(zone);
        this.updatePrivacyZonesList();
      }
      
      // Clean up
      this.endPrivacyZoneSelection();
    });
    
    // Allow canceling with ESC key
    const escListener = (e) => {
      if (e.key === 'Escape') {
        this.endPrivacyZoneSelection();
        document.removeEventListener('keydown', escListener);
      }
    };
    
    document.addEventListener('keydown', escListener);
  }
  
  endPrivacyZoneSelection() {
    // Remove overlay, instructions, and selection box
    const overlay = document.querySelector('.privacy-selection-overlay');
    const instructions = document.querySelector('.selection-instructions');
    const selectionBox = document.querySelector('.selection-box');
    
    if (overlay) overlay.remove();
    if (instructions) instructions.remove();
    if (selectionBox) selectionBox.remove();
    
    this.privacySelectionActive = false;
  }
  
  togglePrivacyZonesPanel() {
    const panel = document.getElementById('privacy-zones-panel');
    const currentDisplay = panel.style.display;
    
    panel.style.display = currentDisplay === 'none' ? 'block' : 'none';
    
    if (panel.style.display === 'block') {
      this.updatePrivacyZonesList();
    }
  }
  
  updatePrivacyZonesList() {
    const zonesList = document.getElementById('privacy-zones-list');
    const zones = this.screenpipe.state.privacyZones;
    
    if (!zones.length) {
      zonesList.innerHTML = '<p>No privacy zones configured</p>';
      return;
    }
    
    // Generate list of zones with remove buttons
    let zonesHTML = '<ul class="privacy-zones">';
    
    zones.forEach((zone, index) => {
      const x = zone.isPercentage ? `${zone.x.toFixed(1)}%` : `${zone.x}px`;
      const y = zone.isPercentage ? `${zone.y.toFixed(1)}%` : `${zone.y}px`;
      const width = zone.isPercentage ? `${zone.width.toFixed(1)}%` : `${zone.width}px`;
      const height = zone.isPercentage ? `${zone.height.toFixed(1)}%` : `${zone.height}px`;
      
      zonesHTML += `
        <li>
          Zone ${index + 1}: ${x}, ${y} (${width} × ${height})
          <button class="remove-zone-btn" data-index="${index}">Remove</button>
        </li>
      `;
    });
    
    zonesHTML += '</ul>';
    zonesList.innerHTML = zonesHTML;
    
    // Add event listeners to remove buttons
    const removeButtons = document.querySelectorAll('.remove-zone-btn');
    removeButtons.forEach(button => {
      button.addEventListener('click', (e) => {
        const index = parseInt(e.target.dataset.index, 10);
        this.screenpipe.removePrivacyZone(index);
        this.updatePrivacyZonesList();
      });
    });
  }
}

// Telehealth integration class
class TelehealthIntegration {
  constructor(screenpipeInstance) {
    this.screenpipe = screenpipeInstance;
    this.currentCall = null;
    this.videoElement = null;
    this.patientStream = null;
  }
  
  async initializeCall(callId, patientId, providerId) {
    try {
      // Initialize call data
      this.currentCall = {
        id: callId || `call_${Date.now()}`,
        patientId,
        providerId,
        startTime: Date.now(),
        status: 'initializing'
      };
      
      // Get user media for video call
      const localStream = await navigator.mediaDevices.getUserMedia({
        video: true,
        audio: true
      });
      
      // Create video elements for local and remote streams
      this.setupVideoElements(localStream);
      
      // In a real implementation, would connect to telehealth service
      // and exchange connection details with patient
      await this.simulateConnection();
      
      // Update call status
      this.currentCall.status = 'connected';
      
      // Start Screenpipe recording automatically
      this.screenpipe.options.patientId = patientId;
      this.screenpipe.options.doctorId = providerId;
      
      if (this.screenpipe.state.hasPatientConsent) {
        await this.screenpipe.startRecording(this.currentCall.id);
      }
      
      return true;
    } catch (error) {
      console.error('Failed to initialize telehealth call:', error);
      return false;
    }
  }
  
  setupVideoElements(localStream) {
    // Create container for video elements if not exists
    let container = document.getElementById('telehealth-video-container');
    if (!container) {
      container = document.createElement('div');
      container.id = 'telehealth-video-container';
      container.style.position = 'fixed';
      container.style.bottom = '20px';
      container.style.right = '20px';
      container.style.zIndex = '1000';
      document.body.appendChild(container);
    }
    
    // Create local video element
    const localVideo = document.createElement('video');
    localVideo.id = 'local-video';
    localVideo.srcObject = localStream;
    localVideo.muted = true; // Mute local video to prevent feedback
    localVideo.autoplay = true;
    localVideo.style.width = '200px';
    localVideo.style.border = '1px solid #000';
    localVideo.style.marginBottom = '10px';
    container.appendChild(localVideo);
    
    // Create remote video element
    const remoteVideo = document.createElement('video');
    remoteVideo.id = 'remote-video';
    remoteVideo.autoplay = true;
    remoteVideo.style.width = '200px';
    remoteVideo.style.border = '1px solid #000';
    container.appendChild(remoteVideo);
    
    this.videoElement = {
      local: localVideo,
      remote: remoteVideo
    };
  }
  
  async simulateConnection() {
    // In a real implementation, would establish WebRTC connection
    // and exchange ICE candidates, SDP offers/answers, etc.
    
    // Simulate connection delay
    await new Promise(resolve => setTimeout(resolve, 1500));
    
    // Simulate receiving remote stream
    // In production, this would be the actual patient stream
    try {
      // Create a placeholder stream for demo purposes
      const canvas = document.createElement('canvas');
      canvas.width = 320;
      canvas.height = 240;
      const ctx = canvas.getContext('2d');
      
      // Create a simple animation for the placeholder stream
      const drawPlaceholder = () => {
        ctx.fillStyle = '#f0f0f0';
        ctx.fillRect(0, 0, canvas.width, canvas.height);
        ctx.fillStyle = '#333';
        ctx.font = '20px Arial';
        ctx.fillText('Patient Video', 100, 120);
        
        // Draw a simple animation
        const time = Date.now() / 1000;
        ctx.beginPath();
        ctx.arc(
          160 + Math.cos(time) * 50,
          120 + Math.sin(time) * 50,
          10,
          0,
          Math.PI * 2
        );
        ctx.fill();
      };
      
      // Start animation loop
      setInterval(drawPlaceholder, 100);
      
      // Use canvas as mock stream
      const stream = canvas.captureStream(30);
      this.patientStream = stream;
      
      // Set as remote video source
      this.videoElement.remote.srcObject = stream;
      
      return true;
    } catch (error) {
      console.error('Error creating simulated stream:', error);
      return false;
    }
  }
  
  endCall() {
    if (!this.currentCall) return false;
    
    // Stop Screenpipe recording if active
    if (this.screenpipe.state.isRecording) {
      this.screenpipe.stopRecording();
    }
    
    // Stop all media tracks
    if (this.videoElement.local.srcObject) {
      this.videoElement.local.srcObject.getTracks().forEach(track => track.stop());
    }
    
    if (this.patientStream) {
      this.patientStream.getTracks().forEach(track => track.stop());
    }
    
    // Remove video elements
    const container = document.getElementById('telehealth-video-container');
    if (container) {
      container.remove();
    }
    
    // Update call data
    this.currentCall.endTime = Date.now();
    this.currentCall.duration = this.currentCall.endTime - this.currentCall.startTime;
    this.currentCall.status = 'ended';
    
    // In a real implementation, would send call data to backend
    console.log('Call ended:', this.currentCall);
    
    // Clear references
    this.videoElement = null;
    this.patientStream = null;
    
    return this.currentCall;
  }
  
  getCallMetrics() {
    if (!this.currentCall) return null;
    
    const now = this.currentCall.status === 'ended' 
      ? this.currentCall.endTime 
      : Date.now();
    
    const duration = now - this.currentCall.startTime;
    
    return {
      callId: this.currentCall.id,
      patientId: this.currentCall.patientId,
      providerId: this.currentCall.providerId,
      status: this.currentCall.status,
      duration: duration,
      formattedDuration: this.formatDuration(duration)
    };
  }
  
  formatDuration(ms) {
    const seconds = Math.floor(ms / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    
    return `${hours}h ${minutes % 60}m ${seconds % 60}s`;
  }
}

// Export classes for use
if (typeof module !== 'undefined' && typeof module.exports !== 'undefined') {
  module.exports = {
    Screenpipe,
    ScreenpipeUI,
    TelehealthIntegration
  };
} else {
  window.Screenpipe = Screenpipe;
  window.ScreenpipeUI = ScreenpipeUI;
  window.TelehealthIntegration = TelehealthIntegration;
}

// Example usage
// const screenpipe = new Screenpipe({
//   autoStart: true,
//   doctorId: 'dr_smith',
//   patientId: 'patient_123'
// });
// 
// const ui = new ScreenpipeUI(screenpipe);
// 
// // For telehealth integration
// const telehealth = new TelehealthIntegration(screenpipe);
// telehealth.initializeCall('call_123', 'patient_123', 'dr_smith');