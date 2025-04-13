// Authentication System - Optimized & Fixed Version

// Core configuration using environment variables with NO default secrets
const config = {
    jwt: {
      secret: process.env.JWT_SECRET,
      expiresIn: process.env.JWT_EXPIRES_IN || '24h',
    },
    baseWallet: {
      apiEndpoint: process.env.BASE_WALLET_API,
      appId: process.env.BASE_WALLET_APP_ID,
      appSecret: process.env.BASE_WALLET_APP_SECRET,
    },
    email: {
      from: process.env.EMAIL_FROM || 'no-reply@example.com',
      baseUrl: process.env.BASE_URL || 'https://example.com',
    }
  };
  
  // Validate critical config
  if (!config.jwt.secret) {
    console.error('JWT_SECRET environment variable is required!');
    process.exit(1);
  }
  
  // Dependencies with improved importing
  const express = require('express');
  const bcrypt = require('bcrypt');
  const jwt = require('jsonwebtoken');
  const mongoose = require('mongoose');
  const ethers = require('ethers');
  const crypto = require('crypto');
  const router = express.Router();
  const speakeasy = require('speakeasy'); // Added for proper 2FA implementation
  const nodemailer = require('nodemailer'); // For actual email sending
  
  // Setup email transport
  const emailTransporter = process.env.NODE_ENV === 'production' 
    ? nodemailer.createTransport({
        // Configure production email settings
        host: process.env.EMAIL_HOST,
        port: process.env.EMAIL_PORT,
        secure: process.env.EMAIL_SECURE === 'true',
        auth: {
          user: process.env.EMAIL_USER,
          pass: process.env.EMAIL_PASS
        }
      })
    : {
        // Dev transport just logs
        sendMail: (opts) => {
          console.log('EMAIL WOULD BE SENT:', opts);
          return Promise.resolve();
        }
      };
  
  // ----- DATABASE MODELS WITH VALIDATION -----
  
  // User Schema with improved validation and security
  const userSchema = new mongoose.Schema({
    email: { 
      type: String, 
      required: function() { return !this.walletAddress; },
      unique: true,
      sparse: true,
      trim: true,
      lowercase: true,
      validate: {
        validator: v => /^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/.test(v),
        message: props => `${props.value} is not a valid email address!`
      }
    },
    password: { 
      type: String, 
      required: function() { return !this.walletAddress; },
      minlength: [8, 'Password must be at least 8 characters']
    },
    walletAddress: { 
      type: String, 
      required: function() { return !this.password; },
      unique: true,
      sparse: true,
      validate: {
        validator: v => /^0x[a-fA-F0-9]{40}$/.test(v),
        message: props => `${props.value} is not a valid Ethereum address!`
      }
    },
    role: { 
      type: String, 
      enum: ['patient', 'doctor', 'admin'], 
      required: true 
    },
    firstName: { type: String, required: true, trim: true },
    lastName: { type: String, required: true, trim: true },
    createdAt: { type: Date, default: Date.now },
    lastLogin: { type: Date },
    lastLogout: { type: Date },
    isVerified: { type: Boolean, default: false },
    isActive: { type: Boolean, default: true },
    verificationToken: { type: String },
    verificationExpires: { type: Date },
    passwordResetToken: { type: String },
    passwordResetExpires: { type: Date },
    twoFactorAuth: {
      enabled: { type: Boolean, default: false },
      secret: { type: String },
      backupCodes: [String]
    },
    activeSessions: [{ 
      token: String,
      userAgent: String,
      ip: String,
      lastActive: { type: Date, default: Date.now },
      expiresAt: Date
    }]
  });
  
  // Combined virtuals and methods
  userSchema.virtual('fullName').get(function() {
    return `${this.firstName} ${this.lastName}`;
  });
  
  // Pre-save middleware for password hashing
  userSchema.pre('save', async function(next) {
    if (!this.isModified('password') || !this.password) return next();
    
    try {
      const salt = await bcrypt.genSalt(10);
      this.password = await bcrypt.hash(this.password, salt);
      next();
    } catch (error) {
      next(error);
    }
  });
  
  // Optimized password comparison
  userSchema.methods.comparePassword = async function(candidatePassword) {
    if (!this.password) return false;
    return bcrypt.compare(candidatePassword, this.password);
  };
  
  // Add session tracking methods
  userSchema.methods.addSession = function(token, userAgent, ip) {
    // Parse expiration from token
    const decoded = jwt.decode(token);
    if (!decoded || !decoded.exp) return;
    
    const expiresAt = new Date(decoded.exp * 1000);
    
    this.activeSessions.push({
      token,
      userAgent,
      ip,
      expiresAt
    });
  };
  
  userSchema.methods.removeSession = function(token) {
    this.activeSessions = this.activeSessions.filter(s => s.token !== token);
  };
  
  userSchema.methods.cleanExpiredSessions = function() {
    const now = new Date();
    this.activeSessions = this.activeSessions.filter(s => s.expiresAt > now);
  };
  
  // Audit logging hooks
  userSchema.post('save', function(doc) {
    console.log(`User ${doc._id} saved: ${doc.email || doc.walletAddress}`);
    // In production: eventEmitter.emit('user:saved', { userId: doc._id });
  });
  
  userSchema.post('remove', function(doc) {
    console.log(`User ${doc._id} removed: ${doc.email || doc.walletAddress}`);
    // In production: eventEmitter.emit('user:removed', { userId: doc._id });
  });
  
  // Create Audit Log schema for proper logging
  const auditLogSchema = new mongoose.Schema({
    user: { 
      type: mongoose.Schema.Types.ObjectId, 
      ref: 'User',
      index: true 
    },
    action: { 
      type: String, 
      required: true,
      index: true
    },
    ip: String,
    userAgent: String,
    details: mongoose.Schema.Types.Mixed,
    timestamp: { 
      type: Date, 
      default: Date.now,
      index: true
    }
  });
  
  // Patient Profile Schema with improved structure
  const patientProfileSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    dateOfBirth: { type: Date },
    gender: { 
      type: String, 
      enum: ['male', 'female', 'other', 'prefer not to say'],
      default: 'prefer not to say'
    },
    phoneNumber: { type: String },
    address: {
      street: { type: String },
      city: { type: String },
      state: { type: String },
      zipCode: { type: String },
      country: { type: String }
    },
    emergencyContact: {
      name: { type: String },
      relationship: { type: String },
      phoneNumber: { type: String }
    },
    medicalHistory: [{ 
      condition: { type: String },
      diagnosedAt: { type: Date },
      notes: { type: String }
    }],
    allergies: [{ type: String }],
    medications: [{
      name: { type: String },
      dosage: { type: String },
      frequency: { type: String },
      startDate: { type: Date }
    }],
    insuranceInfo: {
      provider: { type: String },
      policyNumber: { type: String },
      groupNumber: { type: String }
    }
  });
  
  // Doctor Profile Schema with improved structure
  const doctorProfileSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    specialty: { type: String, required: true },
    licenseNumber: { type: String, required: true },
    education: [{
      institution: { type: String },
      degree: { type: String },
      fieldOfStudy: { type: String },
      from: { type: Date },
      to: { type: Date }
    }],
    workExperience: [{
      institution: { type: String },
      position: { type: String },
      from: { type: Date },
      to: { type: Date }
    }],
    certifications: [{
      name: { type: String },
      issuedBy: { type: String },
      issuedDate: { type: Date },
      expiryDate: { type: Date }
    }],
    availabilityHours: {
      monday: { start: String, end: String },
      tuesday: { start: String, end: String },
      wednesday: { start: String, end: String },
      thursday: { start: String, end: String },
      friday: { start: String, end: String },
      saturday: { start: String, end: String },
      sunday: { start: String, end: String }
    },
    contactInfo: {
      officePhone: { type: String },
      officeAddress: {
        street: { type: String },
        city: { type: String },
        state: { type: String },
        zipCode: { type: String },
        country: { type: String }
      }
    },
    isAcceptingNewPatients: { type: Boolean, default: true }
  });
  
  // Model creation
  const User = mongoose.model('User', userSchema);
  const PatientProfile = mongoose.model('PatientProfile', patientProfileSchema);
  const DoctorProfile = mongoose.model('DoctorProfile', doctorProfileSchema);
  const AuditLog = mongoose.model('AuditLog', auditLogSchema);
  
  // ----- MIDDLEWARE & UTILITIES -----
  
  // Create a logger for audit events
  const createAuditLog = async (userId, action, req, details = {}) => {
    try {
      await new AuditLog({
        user: userId,
        action,
        ip: req.ip,
        userAgent: req.headers['user-agent'],
        details
      }).save();
    } catch (error) {
      console.error('Error creating audit log:', error);
    }
  };
  
  // JWT Authentication middleware with improved error handling and session tracking
  const authenticate = async (req, res, next) => {
    try {
      const authHeader = req.headers.authorization;
      
      if (!authHeader?.startsWith('Bearer ')) {
        return res.status(401).json({ 
          success: false, 
          message: 'Authentication required' 
        });
      }
      
      const token = authHeader.split(' ')[1];
      
      try {
        const decoded = jwt.verify(token, config.jwt.secret);
        req.user = decoded;
        
        // Verify user still exists and is active
        const user = await User.findById(decoded.id);
        
        if (!user) {
          return res.status(401).json({ 
            success: false, 
            message: 'Authentication failed' 
          });
        }
        
        if (!user.isActive) {
          return res.status(403).json({ 
            success: false, 
            message: 'Account is deactivated' 
          });
        }
        
        // Verify token in active sessions
        user.cleanExpiredSessions();
        const tokenExists = user.activeSessions.some(s => s.token === token);
        
        if (!tokenExists) {
          return res.status(401).json({ 
            success: false, 
            message: 'Session expired or revoked' 
          });
        }
        
        // Update session activity
        const sessionIndex = user.activeSessions.findIndex(s => s.token === token);
        if (sessionIndex !== -1) {
          user.activeSessions[sessionIndex].lastActive = new Date();
          await user.save();
        }
        
        next();
      } catch (error) {
        if (error.name === 'TokenExpiredError') {
          return res.status(401).json({ 
            success: false, 
            message: 'Session expired' 
          });
        }
        
        return res.status(401).json({ 
          success: false, 
          message: 'Authentication failed' 
        });
      }
    } catch (error) {
      console.error('Authentication error:', error);
      return res.status(500).json({ 
        success: false, 
        message: 'Internal server error' 
      });
    }
  };
  
  // Role-based authorization
  const authorize = (...roles) => {
    return (req, res, next) => {
      if (!req.user) {
        return res.status(401).json({ success: false, message: 'Authentication required' });
      }
      
      if (!roles.includes(req.user.role)) {
        return res.status(403).json({ success: false, message: 'Access denied' });
      }
      
      next();
    };
  };
  
  // Improved wallet signature verification with ethers.js
  const verifyWalletSignature = async (address, message, signature) => {
    try {
      const signerAddress = ethers.utils.verifyMessage(message, signature);
      return signerAddress.toLowerCase() === address.toLowerCase();
    } catch (error) {
      console.error("Wallet signature verification error:", error);
      return false;
    }
  };
  
  // Enhanced token generation using crypto
  const generateSecureToken = () => crypto.randomBytes(32).toString('hex');
  
  // Actual email service integration
  const sendVerificationEmail = async (user) => {
    if (!user.email || !user.verificationToken) return;
    
    const verificationUrl = `${config.email.baseUrl}/verify-email/${user.verificationToken}`;
    
    await emailTransporter.sendMail({
      from: config.email.from,
      to: user.email,
      subject: 'Verify Your Email Address',
      html: `
        <h1>Email Verification</h1>
        <p>Hello ${user.firstName},</p>
        <p>Please verify your email by clicking the link below:</p>
        <p><a href="${verificationUrl}">Verify Email</a></p>
        <p>This link will expire in 24 hours.</p>
      `
    });
  };
  
  // Actual password reset email implementation
  const sendPasswordResetEmail = async (user) => {
    if (!user.email || !user.passwordResetToken) return;
    
    const resetUrl = `${config.email.baseUrl}/reset-password/${user.passwordResetToken}`;
    
    await emailTransporter.sendMail({
      from: config.email.from,
      to: user.email,
      subject: 'Password Reset Request',
      html: `
        <h1>Password Reset</h1>
        <p>Hello ${user.firstName},</p>
        <p>You requested a password reset. Click the link below to set a new password:</p>
        <p><a href="${resetUrl}">Reset Password</a></p>
        <p>This link will expire in 1 hour.</p>
        <p>If you didn't request this, please ignore this email.</p>
      `
    });
  };
  
  // Email notification about password change
  const sendPasswordChangeNotification = async (user) => {
    if (!user.email) return;
    
    await emailTransporter.sendMail({
      from: config.email.from,
      to: user.email,
      subject: 'Your Password Was Changed',
      html: `
        <h1>Password Changed</h1>
        <p>Hello ${user.firstName},</p>
        <p>Your password was changed successfully.</p>
        <p>If you didn't make this change, please contact support immediately.</p>
      `
    });
  };
  
  // Utility to strip sensitive fields from user object
  const sanitizeUser = (user) => {
    const userObject = user.toObject ? user.toObject() : {...user};
    delete userObject.password;
    delete userObject.verificationToken;
    delete userObject.verificationExpires;
    delete userObject.passwordResetToken;
    delete userObject.passwordResetExpires;
    delete userObject.__v;
    
    // Only show tokens partially
    if (userObject.twoFactorAuth?.secret) {
      userObject.twoFactorAuth.secret = '**hidden**';
    }
    
    // Don't return session tokens
    if (userObject.activeSessions) {
      userObject.activeSessions = userObject.activeSessions.map(session => {
        const { token, ...rest } = session;
        return {
          ...rest,
          id: crypto.createHash('md5').update(token).digest('hex').substring(0, 8)
        };
      });
    }
    
    return userObject;
  };
  
  // Generate JWT token with consistent payload structure
  const generateAuthToken = (user) => {
    const payload = {
      id: user._id,
      role: user.role
    };
    
    // Add email or wallet based on authentication method
    if (user.email) payload.email = user.email;
    if (user.walletAddress) payload.walletAddress = user.walletAddress;
    
    return jwt.sign(payload, config.jwt.secret, { expiresIn: config.jwt.expiresIn });
  };
  
  // ----- AUTHENTICATION ROUTES -----
  
  // Register new user with improved validation
  router.post('/register', async (req, res) => {
    try {
      const { email, password, role, firstName, lastName, specialty, licenseNumber } = req.body;
      
      // Validate request
      if ((!email && !req.body.walletAddress) || (!password && !req.body.walletAddress) || !role || !firstName || !lastName) {
        return res.status(400).json({ 
          success: false, 
          message: 'Required fields missing' 
        });
      }
      
      // Check for existing user
      if (email) {
        const existingUser = await User.findOne({ email });
        if (existingUser) {
          return res.status(400).json({ success: false, message: 'Email already registered' });
        }
      }
      
      if (req.body.walletAddress) {
        const existingWallet = await User.findOne({ walletAddress: req.body.walletAddress });
        if (existingWallet) {
          return res.status(400).json({ success: false, message: 'Wallet already registered' });
        }
      }
      
      if (!['patient', 'doctor'].includes(role)) {
        return res.status(400).json({ success: false, message: 'Invalid role' });
      }
      
      // Doctor validation
      if (role === 'doctor' && (!specialty || !licenseNumber)) {
        return res.status(400).json({ 
          success: false, 
          message: 'Specialty and License Number required for doctors' 
        });
      }
      
      // Create user with verification token
      const verificationToken = generateSecureToken();
      const verificationExpires = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours
      
      const user = new User({
        email,
        password,
        role,
        firstName,
        lastName,
        verificationToken,
        verificationExpires,
        walletAddress: req.body.walletAddress,
        isVerified: !!req.body.walletAddress // Wallet users are auto-verified
      });
      
      await user.save();
      
      // Create role-specific profile
      if (role === 'patient') {
        await new PatientProfile({ user: user._id }).save();
      } else if (role === 'doctor') {
        await new DoctorProfile({
          user: user._id,
          specialty,
          licenseNumber
        }).save();
      }
      
      // Send verification email if needed
      if (email && !user.isVerified) {
        await sendVerificationEmail(user);
      }
      
      // Generate token
      const token = generateAuthToken(user);
      
      // Add session
      user.addSession(token, req.headers['user-agent'], req.ip);
      await user.save();
      
      // Create audit log
      await createAuditLog(user._id, 'REGISTER', req);
      
      res.status(201).json({
        success: true,
        message: user.isVerified ? 
          'Registration successful.' : 
          'Registration successful. Please verify your email.',
        user: sanitizeUser(user),
        token
      });
    } catch (error) {
      console.error('Registration error:', error);
      res.status(500).json({ 
        success: false, 
        message: 'Registration failed', 
        error: process.env.NODE_ENV === 'development' ? error.message : undefined
      });
    }
  });
  
  // Email verification endpoint
  router.get('/verify-email/:token', async (req, res) => {
    try {
      const { token } = req.params;
      
      const user = await User.findOne({ 
        verificationToken: token,
        verificationExpires: { $gt: new Date() }
      });
      
      if (!user) {
        return res.status(400).json({ success: false, message: 'Invalid or expired verification token' });
      }
      
      user.isVerified = true;
      user.verificationToken = undefined;
      user.verificationExpires = undefined;
      await user.save();
      
      // Create audit log
      await createAuditLog(user._id, 'EMAIL_VERIFY', req);
      
      res.status(200).json({
        success: true,
        message: 'Email verified successfully'
      });
    } catch (error) {
      console.error('Email verification error:', error);
      res.status(500).json({ 
        success: false, 
        message: 'Email verification failed', 
        error: process.env.NODE_ENV === 'development' ? error.message : undefined
      });
    }
  });
  
  // Login with email and password
  router.post('/login', async (req, res) => {
    try {
      const { email, password } = req.body;
      
      // Validate request
      if (!email || !password) {
        return res.status(400).json({ 
          success: false, 
          message: 'Email and password are required' 
        });
      }
      
      // Find user
      const user = await User.findOne({ email });
      
      if (!user) {
        // Generic message for security
        return res.status(401).json({ 
          success: false, 
          message: 'Invalid credentials' 
        });
      }
      
      // Check password
      const isPasswordValid = await user.comparePassword(password);
      if (!isPasswordValid) {
        // Create audit log for failed login
        await createAuditLog(user._id, 'LOGIN_FAILED', req, { reason: 'invalid_password' });
        
        return res.status(401).json({ 
          success: false, 
          message: 'Invalid credentials' 
        });
      }
      
      // Check if email is verified
      if (!user.isVerified) {
        // Resend verification email
        user.verificationToken = generateSecureToken();
        user.verificationExpires = new Date(Date.now() + 24 * 60 * 60 * 1000);
        await user.save();
        await sendVerificationEmail(user);
        
        return res.status(403).json({ 
          success: false, 
          message: 'Email not verified. A new verification email has been sent.' 
        });
      }
      
      // Check if user is active
      if (!user.isActive) {
        await createAuditLog(user._id, 'LOGIN_FAILED', req, { reason: 'account_deactivated' });
        
        return res.status(403).json({ 
          success: false, 
          message: 'Account is deactivated. Please contact support.' 
        });
      }
      
      // Check if 2FA is enabled
      if (user.twoFactorAuth?.enabled) {
        // Generate temporary token for 2FA verification
        const tempToken = jwt.sign(
          { id: user._id, require2FA: true },
          config.jwt.secret,
          { expiresIn: '5m' }
        );
        
        await createAuditLog(user._id, 'LOGIN_2FA_REQUESTED', req);
        
        return res.status(200).json({
          success: true,
          message: '2FA verification required',
          requireTwoFactor: true,
          tempToken
        });
      }
      
      // Update last login
      user.lastLogin = Date.now();
      
      // Generate token
      const token = generateAuthToken(user);
      
      // Add session
      user.addSession(token, req.headers['user-agent'], req.ip);
      await user.save();
      
      // Create audit log
      await createAuditLog(user._id, 'LOGIN', req);
      
      res.status(200).json({
        success: true,
        message: 'Login successful',
        user: sanitizeUser(user),
        token
      });
    } catch (error) {
      console.error('Login error:', error);
      res.status(500).json({ 
        success: false, 
        message: 'Login failed', 
        error: process.env.NODE_ENV === 'development' ? error.message : undefined
      });
    }
  });
  
  // Password reset request
  router.post('/forgot-password', async (req, res) => {
    try {
      const { email } = req.body;
      
      if (!email) {
        return res.status(400).json({ 
          success: false, 
          message: 'Email is required' 
        });
      }
      
      // Find user - use generic response regardless of user existence
      const user = await User.findOne({ email });
      
      const genericResponse = {
        success: true, 
        message: 'If your email is in our system, you will receive a reset link shortly' 
      };
      
      if (!user || !user.isActive) return res.status(200).json(genericResponse);
      
      // Generate reset token
      const resetToken = generateSecureToken();
      user.passwordResetToken = resetToken;
      user.passwordResetExpires = new Date(Date.now() + 3600000); // 1 hour
      await user.save();
      
      // Send password reset email
      await sendPasswordResetEmail(user);
      
      // Create audit log
      await createAuditLog(user._id, 'PASSWORD_RESET_REQUEST', req);
      
      res.status(200).json(genericResponse);
    } catch (error) {
      console.error('Password reset request error:', error);
      res.status(500).json({ 
        success: false, 
        message: 'Password reset request failed', 
        error: process.env.NODE_ENV === 'development' ? error.message : undefined
      });
    }
  });
  
  // Reset password with token
  router.post('/reset-password/:token', async (req, res) => {
    try {
      const { token } = req.params;
      const { password } = req.body;
      
      if (!password || password.length < 8) {
        return res.status(400).json({ 
          success: false, 
          message: 'Please provide a password with at least 8 characters' 
        });
      }
      
      // Find user with valid token
      const user = await User.findOne({
        passwordResetToken: token,
        passwordResetExpires: { $gt: new Date() }
      });
      
      if (!user) {
        return res.status(400).json({ 
          success: false, 
          message: 'Invalid or expired reset token' 
        });
      }
      
      // Update password
      user.password = password;
      user.passwordResetToken = undefined;
      user.passwordResetExpires = undefined;
      
      // Invalidate all sessions for security
      user.activeSessions = [];
      
      await user.save();
      
      // Send notification
      await sendPasswordChangeNotification(user);
      
      // Create audit log
      await createAuditLog(user._id, 'PASSWORD_RESET', req);
      
      res.status(200).json({
        success: true,
        message: 'Password reset successful. Please log in with your new password.'
      });
    } catch (error) {
      console.error('Password reset error:', error);
      res.status(500).json({ 
        success: false, 
        message: 'Password reset failed', 
        error: process.env.NODE_ENV === 'development' ? error.message : undefined
      });
    }
  });
  
  // ----- WALLET AUTHENTICATION ROUTES -----
  
  // Generate auth message for wallet
  router.post('/wallet/auth-message', (req, res) => {
    try {
      const { walletAddress } = req.body;
      
      if (!walletAddress || !/^0x[a-fA-F0-9]{40}$/.test(walletAddress)) {
        return res.status(400).json({ 
          success: false, 
          message: 'Valid wallet address is required' 
        });
      }
      
      const timestamp = Date.now();
      const nonce = crypto.randomBytes(16).toString('hex');
      const message = `Login to medical platform with wallet ${walletAddress} at ${timestamp}. Nonce: ${nonce}`;
      
      res.status(200).json({
        success: true,
        data: { message, timestamp, nonce }
      });
    } catch (error) {
      console.error('Auth message generation error:', error);
      res.status(500).json({ 
        success: false, 
        message: 'Failed to generate auth message', 
        error: process.env.NODE_ENV === 'development' ? error.message : undefined
      });
    }
  });
  
  // Login or register with wallet
  router.post('/wallet/login', async (req, res) => {
    try {
      const { walletAddress, signature, message } = req.body;
      
      // Validate inputs
      if (!walletAddress || !signature || !message) {
        return res.status(400).json({ 
          success: false, 
          message: 'Wallet address, signature, and message are required' 
        });
      }
      
      // Wallet validation
      if (!/^0x[a-fA-F0-9]{40}$/.test(walletAddress)) {
        return res.status(400).json({ 
          success: false, 
          message: 'Invalid wallet address format' 
        });
      }
      
      // Verify signature
      const isValidSignature = await verifyWalletSignature(walletAddress, message, signature);
      
      if (!isValidSignature) {
        return res.status(401).json({ 
          success: false, 
          message: 'Invalid signature' 
        });
      }
      
// Find or create user
let user = await User.findOne({ walletAddress });
let isNewUser = false;

if (!user) {
  // Require additional info for new wallet users
  if (!req.body.firstName || !req.body.lastName || !req.body.role) {
    return res.status(400).json({
      success: false,
      message: 'Additional registration info required',
      requiresRegistration: true
    });
  }
  
  // Create new user
  user = new User({
    walletAddress,
    firstName: req.body.firstName,
    lastName: req.body.lastName,
    role: req.body.role,
    isVerified: true, // Wallet users are auto-verified
    isActive: true
  });
  
  await user.save();
  
  // Create role-specific profile
  if (user.role === 'patient') {
    await new PatientProfile({ user: user._id }).save();
  } else if (user.role === 'doctor') {
    if (!req.body.specialty || !req.body.licenseNumber) {
      return res.status(400).json({
        success: false,
        message: 'Specialty and license number required for doctors'
      });
    }
    
    await new DoctorProfile({
      user: user._id,
      specialty: req.body.specialty,
      licenseNumber: req.body.licenseNumber
    }).save();
  }
  
  isNewUser = true;
}

// Check if user is active
if (!user.isActive) {
  await createAuditLog(user._id, 'WALLET_LOGIN_FAILED', req, { reason: 'account_deactivated' });
  
  return res.status(403).json({
    success: false,
    message: 'Account is deactivated. Please contact support.'
  });
}

// Update last login
user.lastLogin = Date.now();

// Generate token
const token = generateAuthToken(user);

// Add session
user.addSession(token, req.headers['user-agent'], req.ip);
await user.save();

// Create audit log
await createAuditLog(user._id, isNewUser ? 'WALLET_REGISTER' : 'WALLET_LOGIN', req);

res.status(200).json({
  success: true,
  message: isNewUser ? 'Registration and login successful' : 'Login successful',
  user: sanitizeUser(user),
  token
});
} catch (error) {
console.error('Wallet login error:', error);
res.status(500).json({
  success: false,
  message: 'Wallet authentication failed',
  error: process.env.NODE_ENV === 'development' ? error.message : undefined
});
}
});

// ----- 2FA ROUTES -----

// Set up 2FA
router.post('/2fa/setup', authenticate, async (req, res) => {
try {
const user = await User.findById(req.user.id);

if (!user) {
  return res.status(404).json({
    success: false,
    message: 'User not found'
  });
}

// Generate new secret
const secret = speakeasy.generateSecret({ length: 20 });

// Generate backup codes
const backupCodes = Array(8).fill(0).map(() => 
  crypto.randomBytes(4).toString('hex')
);

// Save to user
user.twoFactorAuth = {
  enabled: false, // Not enabled until verified
  secret: secret.base32,
  backupCodes
};
await user.save();

// Create audit log
await createAuditLog(user._id, '2FA_SETUP_INITIATED', req);

res.status(200).json({
  success: true,
  data: {
    secret: secret.base32,
    otpauth_url: secret.otpauth_url,
    backupCodes
  }
});
} catch (error) {
console.error('2FA setup error:', error);
res.status(500).json({
  success: false,
  message: '2FA setup failed',
  error: process.env.NODE_ENV === 'development' ? error.message : undefined
});
}
});

// Verify and enable 2FA
router.post('/2fa/verify', authenticate, async (req, res) => {
try {
const { token } = req.body;
const user = await User.findById(req.user.id);

if (!user) {
  return res.status(404).json({
    success: false,
    message: 'User not found'
  });
}

if (!user.twoFactorAuth?.secret) {
  return res.status(400).json({
    success: false,
    message: '2FA not set up yet'
  });
}

const verified = speakeasy.totp.verify({
  secret: user.twoFactorAuth.secret,
  encoding: 'base32',
  token,
  window: 1 // Allow 30 seconds clock drift
});

if (!verified) {
  return res.status(400).json({
    success: false,
    message: 'Invalid verification code'
  });
}

// Enable 2FA
user.twoFactorAuth.enabled = true;
await user.save();

// Create audit log
await createAuditLog(user._id, '2FA_ENABLED', req);

res.status(200).json({
  success: true,
  message: '2FA enabled successfully'
});
} catch (error) {
console.error('2FA verification error:', error);
res.status(500).json({
  success: false,
  message: '2FA verification failed',
  error: process.env.NODE_ENV === 'development' ? error.message : undefined
});
}
});

// Verify 2FA during login
router.post('/2fa/authenticate', async (req, res) => {
try {
const { tempToken, token, backupCode } = req.body;

if (!tempToken || (!token && !backupCode)) {
  return res.status(400).json({
    success: false,
    message: 'Verification code or backup code required'
  });
}

// Verify tempToken
try {
  const decoded = jwt.verify(tempToken, config.jwt.secret);
  
  if (!decoded.require2FA) {
    return res.status(400).json({
      success: false,
      message: 'Invalid temporary token'
    });
  }
  
  const user = await User.findById(decoded.id);
  
  if (!user || !user.isActive) {
    return res.status(401).json({
      success: false,
      message: 'Authentication failed'
    });
  }
  
  let isValid = false;
  
  if (token) {
    // Verify OTP token
    isValid = speakeasy.totp.verify({
      secret: user.twoFactorAuth.secret,
      encoding: 'base32',
      token,
      window: 1 // Allow 30 seconds clock drift
    });
  } else if (backupCode) {
    // Verify backup code
    const backupIndex = user.twoFactorAuth.backupCodes.indexOf(backupCode);
    if (backupIndex !== -1) {
      // Remove used backup code
      user.twoFactorAuth.backupCodes.splice(backupIndex, 1);
      isValid = true;
    }
  }
  
  if (!isValid) {
    await createAuditLog(user._id, '2FA_FAILED', req);
    
    return res.status(401).json({
      success: false,
      message: 'Invalid verification code'
    });
  }
  
  // Update last login
  user.lastLogin = Date.now();
  
  // Generate token
  const authToken = generateAuthToken(user);
  
  // Add session
  user.addSession(authToken, req.headers['user-agent'], req.ip);
  await user.save();
  
  // Create audit log
  await createAuditLog(user._id, 'LOGIN_2FA', req);
  
  res.status(200).json({
    success: true,
    message: 'Authentication successful',
    user: sanitizeUser(user),
    token: authToken
  });
} catch (error) {
  if (error.name === 'TokenExpiredError') {
    return res.status(401).json({
      success: false,
      message: 'Temporary token expired. Please login again.'
    });
  }
  
  throw error;
}
} catch (error) {
console.error('2FA authentication error:', error);
res.status(500).json({
  success: false,
  message: '2FA authentication failed',
  error: process.env.NODE_ENV === 'development' ? error.message : undefined
});
}
});

// Disable 2FA
router.post('/2fa/disable', authenticate, async (req, res) => {
try {
const { password } = req.body;
const user = await User.findById(req.user.id);

if (!user) {
  return res.status(404).json({
    success: false,
    message: 'User not found'
  });
}

// Require password for security if email-based account
if (user.password) {
  if (!password) {
    return res.status(400).json({
      success: false,
      message: 'Password required to disable 2FA'
    });
  }
  
  const isPasswordValid = await user.comparePassword(password);
  if (!isPasswordValid) {
    return res.status(401).json({
      success: false,
      message: 'Invalid password'
    });
  }
}

// Disable 2FA
user.twoFactorAuth = {
  enabled: false,
  secret: undefined,
  backupCodes: []
};
await user.save();

// Create audit log
await createAuditLog(user._id, '2FA_DISABLED', req);

res.status(200).json({
  success: true,
  message: '2FA disabled successfully'
});
} catch (error) {
console.error('2FA disable error:', error);
res.status(500).json({
  success: false,
  message: 'Failed to disable 2FA',
  error: process.env.NODE_ENV === 'development' ? error.message : undefined
});
}
});

// ----- USER MANAGEMENT ROUTES -----

// Logout (current session)
router.post('/logout', authenticate, async (req, res) => {
try {
const authHeader = req.headers.authorization;
const token = authHeader.split(' ')[1];

const user = await User.findById(req.user.id);
if (user) {
  user.removeSession(token);
  user.lastLogout = Date.now();
  await user.save();
  
  // Create audit log
  await createAuditLog(user._id, 'LOGOUT', req);
}

res.status(200).json({
  success: true,
  message: 'Logged out successfully'
});
} catch (error) {
console.error('Logout error:', error);
res.status(500).json({
  success: false,
  message: 'Logout failed',
  error: process.env.NODE_ENV === 'development' ? error.message : undefined
});
}
});

// Logout from all devices
router.post('/logout-all', authenticate, async (req, res) => {
try {
const user = await User.findById(req.user.id);
if (user) {
  user.activeSessions = [];
  user.lastLogout = Date.now();
  await user.save();
  
  // Create audit log
  await createAuditLog(user._id, 'LOGOUT_ALL', req);
}

res.status(200).json({
  success: true,
  message: 'Logged out from all devices'
});
} catch (error) {
console.error('Logout all error:', error);
res.status(500).json({
  success: false,
  message: 'Logout from all devices failed',
  error: process.env.NODE_ENV === 'development' ? error.message : undefined
});
}
});

// Get user profile
router.get('/profile', authenticate, async (req, res) => {
try {
const user = await User.findById(req.user.id);

if (!user) {
  return res.status(404).json({
    success: false,
    message: 'User not found'
  });
}

let profile = null;

if (user.role === 'patient') {
  profile = await PatientProfile.findOne({ user: user._id });
} else if (user.role === 'doctor') {
  profile = await DoctorProfile.findOne({ user: user._id });
}

res.status(200).json({
  success: true,
  data: {
    user: sanitizeUser(user),
    profile
  }
});
} catch (error) {
console.error('Get profile error:', error);
res.status(500).json({
  success: false,
  message: 'Failed to retrieve profile',
  error: process.env.NODE_ENV === 'development' ? error.message : undefined
});
}
});

// Update user profile
router.put('/profile', authenticate, async (req, res) => {
try {
const { firstName, lastName, email, password, newPassword, ...profileData } = req.body;

const user = await User.findById(req.user.id);

if (!user) {
  return res.status(404).json({
    success: false,
    message: 'User not found'
  });
}

// Update basic user info
if (firstName) user.firstName = firstName;
if (lastName) user.lastName = lastName;

// Update email with verification
if (email && email !== user.email) {
  // Check if email exists
  const existingEmail = await User.findOne({ email, _id: { $ne: user._id } });
  if (existingEmail) {
    return res.status(400).json({
      success: false,
      message: 'Email already in use'
    });
  }
  
  user.email = email;
  user.isVerified = false;
  user.verificationToken = generateSecureToken();
  user.verificationExpires = new Date(Date.now() + 24 * 60 * 60 * 1000);
  
  // Send verification email
  await sendVerificationEmail(user);
}

// Change password if provided
if (newPassword) {
  // If account has password, verify current password
  if (user.password && !password) {
    return res.status(400).json({
      success: false,
      message: 'Current password is required'
    });
  }
  
  if (user.password) {
    const isPasswordValid = await user.comparePassword(password);
    if (!isPasswordValid) {
      return res.status(401).json({
        success: false,
        message: 'Current password is incorrect'
      });
    }
  }
  
  // Update password
  user.password = newPassword;
  
  // Send notification
  await sendPasswordChangeNotification(user);
  
  // Force logout from all devices except current
  const currentToken = req.headers.authorization.split(' ')[1];
  const currentSession = user.activeSessions.find(s => s.token === currentToken);
  user.activeSessions = currentSession ? [currentSession] : [];
}

await user.save();

// Update profile if data provided
if (Object.keys(profileData).length > 0) {
  let profile = null;
  
  if (user.role === 'patient') {
    profile = await PatientProfile.findOneAndUpdate(
      { user: user._id },
      { $set: profileData },
      { new: true, runValidators: true }
    );
  } else if (user.role === 'doctor') {
    profile = await DoctorProfile.findOneAndUpdate(
      { user: user._id },
      { $set: profileData },
      { new: true, runValidators: true }
    );
  }
}

// Create audit log
await createAuditLog(user._id, 'PROFILE_UPDATE', req);

res.status(200).json({
  success: true,
  message: 'Profile updated successfully',
  user: sanitizeUser(user)
});
} catch (error) {
console.error('Update profile error:', error);
res.status(500).json({
  success: false,
  message: 'Failed to update profile',
  error: process.env.NODE_ENV === 'development' ? error.message : undefined
});
}
});

// Deactivate account
router.post('/deactivate', authenticate, async (req, res) => {
try {
const { password } = req.body;
const user = await User.findById(req.user.id);

if (!user) {
  return res.status(404).json({
    success: false,
    message: 'User not found'
  });
}

// Require password for email-based accounts
if (user.password) {
  if (!password) {
    return res.status(400).json({
      success: false,
      message: 'Password required to deactivate account'
    });
  }
  
  const isPasswordValid = await user.comparePassword(password);
  if (!isPasswordValid) {
    return res.status(401).json({
      success: false,
      message: 'Invalid password'
    });
  }
}

// Deactivate account
user.isActive = false;
user.activeSessions = [];
await user.save();

// Create audit log
await createAuditLog(user._id, 'ACCOUNT_DEACTIVATE', req);

res.status(200).json({
  success: true,
  message: 'Account deactivated successfully'
});
} catch (error) {
console.error('Account deactivation error:', error);
res.status(500).json({
  success: false,
  message: 'Failed to deactivate account',
  error: process.env.NODE_ENV === 'development' ? error.message : undefined
});
}
});

// List active sessions
router.get('/sessions', authenticate, async (req, res) => {
try {
const user = await User.findById(req.user.id);

if (!user) {
  return res.status(404).json({
    success: false,
    message: 'User not found'
  });
}

// Clean expired sessions first
user.cleanExpiredSessions();
await user.save();

// Get sessions without tokens
const sessions = user.activeSessions.map(session => {
  const { token, ...sessionData } = session.toObject();
  return {
    ...sessionData,
    id: crypto.createHash('md5').update(token).digest('hex').substring(0, 8),
    current: token === req.headers.authorization.split(' ')[1]
  };
});

res.status(200).json({
  success: true,
  data: sessions
});
} catch (error) {
console.error('List sessions error:', error);
res.status(500).json({
  success: false,
  message: 'Failed to list sessions',
  error: process.env.NODE_ENV === 'development' ? error.message : undefined
});
}
});

// Revoke specific session
router.delete('/sessions/:id', authenticate, async (req, res) => {
try {
const { id } = req.params;
const user = await User.findById(req.user.id);

if (!user) {
  return res.status(404).json({
    success: false,
    message: 'User not found'
  });
}

// Find session by hashed ID
const session = user.activeSessions.find(s => {
  const hashedToken = crypto.createHash('md5').update(s.token).digest('hex').substring(0, 8);
  return hashedToken === id;
});

if (!session) {
  return res.status(404).json({
    success: false,
    message: 'Session not found'
  });
}

// Check if trying to revoke current session
const currentToken = req.headers.authorization.split(' ')[1];
if (session.token === currentToken) {
  return res.status(400).json({
    success: false,
    message: 'Cannot revoke current session. Use logout instead.'
  });
}

// Remove session
user.removeSession(session.token);
await user.save();

// Create audit log
await createAuditLog(user._id, 'SESSION_REVOKE', req, { sessionId: id });

res.status(200).json({
  success: true,
  message: 'Session revoked successfully'
});
} catch (error) {
console.error('Revoke session error:', error);
res.status(500).json({
  success: false,
  message: 'Failed to revoke session',
  error: process.env.NODE_ENV === 'development' ? error.message : undefined
});
}
});

// ----- ADMIN ROUTES -----

// Get all users (admin only)
router.get('/users', authenticate, authorize('admin'), async (req, res) => {
try {
const { page = 1, limit = 10, role, search, status } = req.query;

// Build query
const query = {};

if (role) query.role = role;
if (status === 'active') query.isActive = true;
if (status === 'inactive') query.isActive = false;

if (search) {
  query.$or = [
    { firstName: { $regex: search, $options: 'i' } },
    { lastName: { $regex: search, $options: 'i' } },
    { email: { $regex: search, $options: 'i' } }
  ];
}

// Get users with pagination
const users = await User.find(query)
  .select('-password -verificationToken -verificationExpires -passwordResetToken -passwordResetExpires')
  .sort({ createdAt: -1 })
  .limit(limit * 1)
  .skip((page - 1) * limit);

// Get total count
const count = await User.countDocuments(query);

res.status(200).json({
  success: true,
  data: {
    users: users.map(sanitizeUser),
    totalPages: Math.ceil(count / limit),
    currentPage: page,
    totalUsers: count
  }
});
} catch (error) {
console.error('Get users error:', error);
res.status(500).json({
  success: false,
  message: 'Failed to retrieve users',
  error: process.env.NODE_ENV === 'development' ? error.message : undefined
});
}
});

// Admin: Toggle user active status
router.put('/users/:id/toggle-status', authenticate, authorize('admin'), async (req, res) => {
try {
const { id } = req.params;

const user = await User.findById(id);

if (!user) {
  return res.status(404).json({
    success: false,
    message: 'User not found'
  });
}

// Toggle status
user.isActive = !user.isActive;

// If deactivating, invalidate all sessions
if (!user.isActive) {
  user.activeSessions = [];
}

await user.save();

// Create audit log
await createAuditLog(
  req.user.id, 
  user.isActive ? 'ADMIN_ACTIVATE_USER' : 'ADMIN_DEACTIVATE_USER', 
  req,
  { targetUserId: id }
);

res.status(200).json({
  success: true,
  message: `User ${user.isActive ? 'activated' : 'deactivated'} successfully`,
  user: sanitizeUser(user)
});
} catch (error) {
console.error('Toggle user status error:', error);
res.status(500).json({
  success: false,
  message: 'Failed to update user status',
  error: process.env.NODE_ENV === 'development' ? error.message : undefined
});
}
});

// Get audit logs (admin only)
router.get('/audit-logs', authenticate, authorize('admin'), async (req, res) => {
try {
const { page = 1, limit = 20, userId, action, startDate, endDate } = req.query;

// Build query
const query = {};

if (userId) query.user = userId;
if (action) query.action = action;

// Date range
if (startDate || endDate) {
  query.timestamp = {};
  if (startDate) query.timestamp.$gte = new Date(startDate);
  if (endDate) query.timestamp.$lte = new Date(endDate);
}

// Get logs with pagination
const logs = await AuditLog.find(query)
  .populate('user', 'firstName lastName email walletAddress')
  .sort({ timestamp: -1 })
  .limit(limit * 1)
  .skip((page - 1) * limit);

// Get total count
const count = await AuditLog.countDocuments(query);

res.status(200).json({
  success: true,
  data: {
    logs,
    totalPages: Math.ceil(count / limit),
    currentPage: page,
    totalLogs: count
  }
});
} catch (error) {
console.error('Get audit logs error:', error);
res.status(500).json({
  success: false,
  message: 'Failed to retrieve audit logs',
  error: process.env.NODE_ENV === 'development' ? error.message : undefined
});
}
});

// Health check route
router.get('/health', (req, res) => {
res.status(200).json({
success: true,
message: 'Authentication service is running',
timestamp: new Date().toISOString()
});
});

module.exports = router;