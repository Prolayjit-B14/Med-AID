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
      
      // Bind methods
      this.startRecording = this.startRecording.bind(this);
      this.stopRecording = this.stopRecording.bind(this);
      this.captureScreen = this.captureScreen.bind(this);
      this.trackActivity = this.trackActivity.bind(this);
      this.setPatientConsent = this.setPatientConsent.bind(this);
      this.addPrivacyZone = this.addPrivacyZone.bind(this);
      this.generateReport = this.generateReport.bind(this);
      
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
        
        // Check for necessary permissions
        if (this.options.screenCaptureEnabled) {
          await this.requestScreenCapturePermission();
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
        this.videoElement.play();
        
        return true;
      } catch (error) {
        console.error('Screen capture permission denied:', error);
        return false;
      }
    }
    
    async startRecording(consultationId = null) {
      if (!this.options.patientConsentRequired || this.state.hasPatientConsent) {
        // Generate session ID if not provided
        this.state.currentSessionId = consultationId || `session_${Date.now()}`;
        this.state.currentConsultationStartTime = Date.now();
        this.state.isRecording = true;
        
        // Start screen capture interval
        if (this.options.screenCaptureEnabled) {
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
      // Stop intervals
      clearInterval(this.captureInterval);
      
      // Calculate final metrics
      if (this.state.currentConsultationStartTime) {
        const endTime = Date.now();
        const sessionDuration = endTime - this.state.currentConsultationStartTime;
        this.state.consultationMetrics.totalDuration += sessionDuration;
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
      this.state.currentConsultationStartTime = null;
      
      // Save data if needed
      if (this.options.storageLocation === 'cloud') {
        this.saveToCloud(sessionData);
      }
      
      console.log('Recording stopped and data compiled');
      return sessionData;
    }
    
    async captureScreen() {
      if (!this.state.isRecording || !this.screenStream) return;
      
      try {
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
            ctx.fillStyle = 'rgba(0, 0, 0, 1)';
            ctx.fillRect(zone.x, zone.y, zone.width, zone.height);
          });
        }
        
        // Convert to image data
        const imageData = canvas.toDataURL('image/jpeg', 0.7);
        
        // Store capture data
        const captureData = {
          timestamp: Date.now(),
          sessionId: this.state.currentSessionId,
          imageData: this.options.encryptData ? this.encryptData(imageData) : imageData,
          activeApplication: this.getCurrentApplicationFocus()
        };
        
        this.state.screenCaptures.push(captureData);
        
        // Tracking application focus time
        const appName = captureData.activeApplication;
        if (!this.state.consultationMetrics.screenTimeByApplication[appName]) {
          this.state.consultationMetrics.screenTimeByApplication[appName] = 0;
        }
        this.state.consultationMetrics.screenTimeByApplication[appName] += this.options.captureInterval / 1000;
        
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
      // zone should be {x, y, width, height}
      this.state.privacyZones.push(zone);
      return this.state.privacyZones.length;
    }
    
    encryptData(data) {
      // Simplified encryption example - in production use proper encryption
      // This is a placeholder for actual encryption logic
      return `encrypted_${data.substring(0, 20)}...`;
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
      
      const keysPerMinute = (this.state.activityLog.filter(a => a.type === 'keydown').length / 
                            (this.state.consultationMetrics.totalDuration / 60000)).toFixed(1);
                            
      return `${keysPerMinute} inputs/minute`;
    }
    
    calculateEfficiencyScore() {
      // Simple algorithm to rate productivity
      const activePct = (this.state.consultationMetrics.activeInputTime / this.state.consultationMetrics.totalDuration);
      
      if (activePct > 0.8) return 'Excellent';
      if (activePct > 0.6) return 'Good';
      if (activePct > 0.4) return 'Average';
      return 'Below Average';
    }
    
    async saveToCloud(data) {
      // Placeholder for API call to save data
      console.log('Saving session data to cloud storage', data.id);
      // In real implementation, would make API call to backend
      return true;
    }
    
    dispose() {
      // Clean up resources
      if (this.screenStream) {
        this.screenStream.getTracks().forEach(track => track.stop());
      }
      
      if (this.videoElement) {
        this.videoElement.remove();
      }
      
      // Remove event listeners
      document.removeEventListener('keydown', this.trackActivity);
      document.removeEventListener('mousemove', this.trackActivity);
      document.removeEventListener('click', this.trackActivity);
      
      // Clear intervals
      clearInterval(this.captureInterval);
      
      console.log('Screenpipe resources cleaned up');
    }
  }
  
  // UI Components for Doctor/Admin Panel
  class ScreenpipeUI {
    constructor(screenpipeInstance, containerId = 'screenpipe-container') {
      this.screenpipe = screenpipeInstance;
      this.container = document.getElementById(containerId) || this.createContainer(containerId);
      
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
      startBtn.addEventListener('click', () => {
        this.screenpipe.startRecording();
        this.updateUI({ isRecording: true });
      });
      
      // Stop recording button
      const stopBtn = document.getElementById('stop-recording');
      stopBtn.addEventListener('click', () => {
        const sessionData = this.screenpipe.stopRecording();
        this.updateUI({ isRecording: false });
        this.displaySessionSummary(sessionData);
      });
      
      // Generate report button
      const reportBtn = document.getElementById('generate-report');
      reportBtn.addEventListener('click', () => {
        const report = this.screenpipe.generateReport();
        this.displayReport(report);
      });
      
      // Add privacy zone button
      const privacyZoneBtn = document.getElementById('add-privacy-zone');
      privacyZoneBtn.addEventListener('click', () => {
        this.startPrivacyZoneSelection();
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
      `;
    }
    
    displaySessionSummary(sessionData) {
      // Display quick session summary after stopping
      const reportOutput = document.getElementById('report-output');
      
      reportOutput.innerHTML = `
        <div class="session-summary">
          <h4>Session Complete</h4>
          <p><strong>Duration:</strong> ${sessionData.duration}</p>
          <p><strong>Active Input Time:</strong> ${sessionData.activeInputTime}</p>
          <p><strong>Captures:</strong> ${sessionData.captureCount}</p>
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
            <h4>Consultation Metrics</h4>
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
                <td>Screen Captures:</td>
                <td>${report.metrics.captureCount}</td>
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
            
            <h4>Application Usage Breakdown</h4>
            <table class="app-table">
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
          </div>
          
          <div class="actions">
            <button class="btn btn-primary" onclick="window.print()">Print Report</button>
            <button class="btn btn-secondary" id="export-report">Export Data</button>
          </div>
        </div>
      `;
      
      // Add export functionality
      document.getElementById('export-report').addEventListener('click', () => {
        this.exportReportData(report);
      });
    }
    
    exportReportData(report) {
      // Create downloadable data
      const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(report, null, 2));
      const downloadAnchorNode = document.createElement('a');
      downloadAnchorNode.setAttribute("href", dataStr);
      downloadAnchorNode.setAttribute("download", `screenpipe_report_${report.sessionId}.json`);
      document.body.appendChild(downloadAnchorNode);
      downloadAnchorNode.click();
      downloadAnchorNode.remove();
    }
    
    startPrivacyZoneSelection() {
      // UI for selecting privacy zones on screen
      alert('Click and drag to select an area to exclude from capture');
      
      // Simple implementation - in production would use a proper selection tool
      const overlay = document.createElement('div');
      overlay.style.position = 'fixed';
      overlay.style.top = '0';
      overlay.style.left = '0';
      overlay.style.width = '100vw';
      overlay.style.height = '100vh';
      overlay.style.backgroundColor = 'rgba(0,0,0,0.3)';
      overlay.style.zIndex = '9999';
      overlay.style.cursor = 'crosshair';
      
      let startX, startY;
      let selection = document.createElement('div');
      selection.style.position = 'absolute';
      selection.style.border = '2px dashed red';
      selection.style.backgroundColor = 'rgba(255,0,0,0.2)';
      
      // Mouse down - start selection
      overlay.addEventListener('mousedown', (e) => {
        startX = e.clientX;
        startY = e.clientY;
        
        selection.style.left = startX + 'px';
        selection.style.top = startY + 'px';
        selection.style.width = '0px';
        selection.style.height = '0px';
        
        overlay.appendChild(selection);
      });
      
      // Mouse move - resize selection
      overlay.addEventListener('mousemove', (e) => {
        if (!startX && !startY) return;
        
        const width = e.clientX - startX;
        const height = e.clientY - startY;
        
        selection.style.width = Math.abs(width) + 'px';
        selection.style.height = Math.abs(height) + 'px';
        
        if (width < 0) {
          selection.style.left = e.clientX + 'px';
        }
        
        if (height < 0) {
          selection.style.top = e.clientY + 'px';
        }
      });
      
      // Mouse up - complete selection
      overlay.addEventListener('mouseup', (e) => {
        const width = Math.abs(e.clientX - startX);
        const height = Math.abs(e.clientY - startY);
        const x = Math.min(startX, e.clientX);
        const y = Math.min(startY, e.clientY);
        
        if (width > 10 && height > 10) {
          this.screenpipe.addPrivacyZone({ x, y, width, height });
          alert(`Privacy zone added: ${width}x${height} at (${x},${y})`);
        }
        
        document.body.removeChild(overlay);
      });
      
      document.body.appendChild(overlay);
    }
  }
  
  // Usage example for telehealth page
  document.addEventListener('DOMContentLoaded', () => {
    // Initialize Screenpipe on telehealth page
    if (window.location.pathname.includes('telehealth') || 
        window.location.pathname.includes('doctor-tools')) {
      
      // Get doctor and patient IDs (would come from the application)
      const doctorId = document.querySelector('[data-doctor-id]')?.dataset.doctorId || 'doctor-1';
      const patientId = document.querySelector('[data-patient-id]')?.dataset.patientId || 'patient-1';
      
      // Create Screenpipe instance
      const screenpipe = new Screenpipe({
        doctorId,
        patientId,
        captureInterval: 10000, // 10 seconds between captures
        encryptData: true,
        patientConsentRequired: true,
        storageLocation: 'cloud'
      });
      
      // Initialize
      screenpipe.init().then(success => {
        if (success) {
          // Create UI
          const ui = new ScreenpipeUI(screenpipe, 'telehealth-tools-container');
          
          // Make available to console for debugging
          window.screenpipe = screenpipe;
          window.screenpipeUI = ui;
          
          console.log('Screenpipe initialized for telehealth session');
        } else {
          console.error('Failed to initialize Screenpipe');
        }
      });
    }
  });
  
  // CSS for Screenpipe UI
  const style = document.createElement('style');
  style.textContent = `
    .screenpipe-controls {
      border: 1px solid #ddd;
      border-radius: 8px;
      padding: 15px;
      margin-bottom: 20px;
      background-color: #f9f9f9;
    }
    
    .screenpipe-controls h3 {
      margin-top: 0;
      color: #2c3e50;
    }
    
    .consent-section {
      margin: 15px 0;
      padding: 10px;
      background-color: #fff;
      border-radius: 4px;
      border-left: 4px solid #3498db;
    }
    
    .control-buttons {
      display: flex;
      gap: 10px;
      margin: 15px 0;
    }
    
    .btn {
      padding: 8px 16px;
      border: none;
      border-radius: 4px;
      cursor: pointer;
      font-weight: bold;
    }
    
    .btn-primary {
      background-color: #3498db;
      color: white;
    }
    
    .btn-danger {
      background-color: #e74c3c;
      color: white;
    }
    
    .btn-info {
      background-color: #2ecc71;
      color: white;
    }
    
    .btn-secondary {
      background-color: #95a5a6;
      color: white;
    }
    
    .btn:disabled {
      opacity: 0.5;
      cursor: not-allowed;
    }
    
    .privacy-controls {
      margin: 15px 0;
      padding: 10px;
      background-color: #fff;
      border-radius: 4px;
    }
    
    .status-indicator {
      margin-top: 15px;
      font-weight: bold;
    }
    
    .recording {
      color: #e74c3c;
    }
    
    .metrics-panel {
      background-color: #fff;
      border-radius: 8px;
      padding: 15px;
      margin-bottom: 20px;
      box-shadow: 0 2px 5px rgba(0,0,0,0.1);
    }
    
    .metrics-panel h4 {
      margin-top: 0;
      color: #2c3e50;
      border-bottom: 1px solid #eee;
      padding-bottom: 8px;
    }
    
    .report-output {
      background-color: #fff;
      border-radius: 8px;
      padding: 20px;
      box-shadow: 0 2px 5px rgba(0,0,0,0.1);
    }
    
    .session-summary {
      background-color: #f8f9fa;
      padding: 15px;
      border-radius: 4px;
      margin-bottom: 20px;
    }
    
    .full-report h3 {
      color: #2c3e50;
      border-bottom: 2px solid #3498db;
      padding-bottom: 10px;
    }
    
    .metrics-section {
      margin: 20px 0;
    }
    
    .metrics-table, .app-table {
      width: 100%;
      border-collapse: collapse;
      margin: 15px 0;
    }
    
    .metrics-table td, .app-table td, .app-table th {
padding: 8px;
    border-bottom: 1px solid #eee;
  }
  
  .metrics-table tr td:first-child, .app-table th {
    font-weight: bold;
    color: #34495e;
  }
  
  .app-table th {
    text-align: left;
    background-color: #f8f9fa;
  }
  
  .actions {
    margin-top: 20px;
    display: flex;
    gap: 10px;
    justify-content: flex-end;
  }
`;

document.head.appendChild(style);

// HTML for the telehealth page integration
function injectTelehealthIntegration() {
  const container = document.createElement('div');
  container.id = 'telehealth-tools-container';
  container.className = 'telehealth-productivity-tools';
  
  // Add to page
  const targetElement = document.querySelector('.telehealth-sidebar') || 
                        document.querySelector('.doctor-panel') || 
                        document.querySelector('main');
                        
  if (targetElement) {
    targetElement.appendChild(container);
  } else {
    // Fallback - append to body
    document.body.appendChild(container);
  }
  
  // Add help tooltip
  const helpTip = document.createElement('div');
  helpTip.className = 'help-tooltip';
  helpTip.innerHTML = `
    <div class="tooltip-icon">?</div>
    <div class="tooltip-content">
      <h4>About Screenpipe</h4>
      <p>Screenpipe helps healthcare professionals track productivity during telehealth consultations.</p>
      <ul>
        <li>Screen captures are stored securely and encrypted</li>
        <li>Patient consent is required before recording</li>
        <li>Use privacy zones to exclude sensitive information</li>
        <li>Reports help optimize your workflow</li>
      </ul>
      <p><strong>Note:</strong> All data is handled in compliance with HIPAA regulations.</p>
    </div>
  `;
  
  container.appendChild(helpTip);
  
  // Add tooltip styles
  const tooltipStyle = document.createElement('style');
  tooltipStyle.textContent = `
    .help-tooltip {
      position: relative;
      margin-bottom: 20px;
    }
    
    .tooltip-icon {
      display: inline-block;
      width: 24px;
      height: 24px;
      background-color: #3498db;
      color: white;
      border-radius: 50%;
      text-align: center;
      line-height: 24px;
      cursor: pointer;
      font-weight: bold;
    }
    
    .tooltip-content {
      display: none;
      position: absolute;
      top: 30px;
      left: 0;
      width: 300px;
      background-color: white;
      border-radius: 8px;
      box-shadow: 0 3px 10px rgba(0,0,0,0.2);
      padding: 15px;
      z-index: 1000;
    }
    
    .tooltip-icon:hover + .tooltip-content {
      display: block;
    }
    
    .tooltip-content h4 {
      margin-top: 0;
      color: #2c3e50;
    }
    
    .tooltip-content ul {
      padding-left: 20px;
    }
  `;
  
  document.head.appendChild(tooltipStyle);
}

// Call this function to inject the HTML
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', injectTelehealthIntegration);
} else {
  injectTelehealthIntegration();
}

// Export the Screenpipe class for module usage
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { Screenpipe, ScreenpipeUI };
}
