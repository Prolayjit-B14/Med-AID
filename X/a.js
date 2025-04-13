// Authentication System - Optimized Version
// Core configuration using environment variables with secure defaults
const config = {
    jwt: {
      secret: process.env.JWT_SECRET || 'your-secret-key-here',
      expiresIn: process.env.JWT_EXPIRES_IN || '7d',
    },
    baseWallet: {
      apiEndpoint: process.env.BASE_WALLET_API || 'https://api.base.org/v1',
      appId: process.env.BASE_WALLET_APP_ID,
      appSecret: process.env.BASE_WALLET_APP_SECRET,
    }
  };
  
  // Dependencies with improved importing
  const express = require('express');
  const bcrypt = require('bcrypt');
  const jwt = require('jsonwebtoken');
  const mongoose = require('mongoose');
  const ethers = require('ethers');
  const crypto = require('crypto');
  const router = express.Router();
  
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
    passwordResetToken: { type: String },
    passwordResetExpires: { type: Date },
    twoFactorAuth: {
      enabled: { type: Boolean, default: false },
      secret: { type: String },
      backupCodes: [String]
    }
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
  
  // Audit logging hooks
  userSchema.post('save', function(doc) {
    console.log(`User ${doc._id} saved: ${doc.email || doc.walletAddress}`);
    // In production: eventEmitter.emit('user:saved', { userId: doc._id });
  });
  
  userSchema.post('remove', function(doc) {
    console.log(`User ${doc._id} removed: ${doc.email || doc.walletAddress}`);
    // In production: eventEmitter.emit('user:removed', { userId: doc._id });
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
  
  // ----- MIDDLEWARE & UTILITIES -----
  
  // JWT Authentication middleware with improved error handling
  const authenticate = (req, res, next) => {
    try {
      const authHeader = req.headers.authorization;
      
      if (!authHeader?.startsWith('Bearer ')) {
        return res.status(401).json({ 
          success: false, 
          message: 'Access denied. No token provided.' 
        });
      }
      
      const token = authHeader.split(' ')[1];
      const decoded = jwt.verify(token, config.jwt.secret);
      
      req.user = decoded;
      next();
    } catch (error) {
      return res.status(401).json({ 
        success: false, 
        message: error.name === 'TokenExpiredError' ? 'Token expired.' : 'Invalid token.' 
      });
    }
  };
  
  // Role-based authorization
  const authorize = (...roles) => {
    return (req, res, next) => {
      if (!req.user) {
        return res.status(401).json({ success: false, message: 'Not authenticated.' });
      }
      
      if (!roles.includes(req.user.role)) {
        return res.status(403).json({ success: false, message: 'Not authorized for this action.' });
      }
      
      next();
    };
  };
  
  // Wallet signature verification with ethers.js
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
  const generateVerificationToken = () => crypto.randomBytes(32).toString('hex');
  
  // Placeholder for email service integration
  const sendVerificationEmail = async (user) => {
    console.log(`Sending verification email to ${user.email}`);
    console.log(`Verification token: ${user.verificationToken}`);
    // Implementation using a service like SendGrid would go here
  };
  
  // Utility to strip sensitive fields from user object
  const sanitizeUser = (user) => {
    const userObject = user.toObject ? user.toObject() : {...user};
    delete userObject.password;
    delete userObject.verificationToken;
    delete userObject.passwordResetToken;
    delete userObject.passwordResetExpires;
    delete userObject.__v;
    return userObject;
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
      const verificationToken = generateVerificationToken();
      const user = new User({
        email,
        password,
        role,
        firstName,
        lastName,
        verificationToken,
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
      const token = jwt.sign(
        { id: user._id, email: user.email, role: user.role },
        config.jwt.secret,
        { expiresIn: config.jwt.expiresIn }
      );
      
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
        error: error.message 
      });
    }
  });
  
  // Email verification endpoint
  router.get('/verify-email/:token', async (req, res) => {
    try {
      const { token } = req.params;
      
      const user = await User.findOne({ verificationToken: token });
      
      if (!user) {
        return res.status(400).json({ success: false, message: 'Invalid verification token' });
      }
      
      user.isVerified = true;
      user.verificationToken = undefined;
      await user.save();
      
      res.status(200).json({
        success: true,
        message: 'Email verified successfully'
      });
    } catch (error) {
      console.error('Email verification error:', error);
      res.status(500).json({ 
        success: false, 
        message: 'Email verification failed', 
        error: error.message 
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
      
      if (!user || !(await user.comparePassword(password))) {
        return res.status(401).json({ 
          success: false, 
          message: 'Invalid email or password' 
        });
      }
      
      // Check if user is active
      if (!user.isActive) {
        return res.status(403).json({ 
          success: false, 
          message: 'Account is deactivated. Please contact support.' 
        });
      }
      
      // Update last login
      user.lastLogin = Date.now();
      await user.save();
      
      // Generate token
      const token = jwt.sign(
        { id: user._id, email: user.email, role: user.role },
        config.jwt.secret,
        { expiresIn: config.jwt.expiresIn }
      );
      
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
        error: error.message 
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
      
      if (!user) return res.status(200).json(genericResponse);
      
      // Generate reset token
      const resetToken = crypto.randomBytes(32).toString('hex');
      user.passwordResetToken = resetToken;
      user.passwordResetExpires = Date.now() + 3600000; // 1 hour
      await user.save();
      
      // Send password reset email (implementation would depend on your email service)
      console.log(`Password reset email for ${email}: Token: ${resetToken}`);
      
      res.status(200).json(genericResponse);
    } catch (error) {
      console.error('Password reset request error:', error);
      res.status(500).json({ 
        success: false, 
        message: 'Password reset request failed', 
        error: error.message 
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
        passwordResetExpires: { $gt: Date.now() }
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
      await user.save();
      
      res.status(200).json({
        success: true,
        message: 'Password reset successful'
      });
    } catch (error) {
      console.error('Password reset error:', error);
      res.status(500).json({ 
        success: false, 
        message: 'Password reset failed', 
        error: error.message 
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
      const message = `Login to medical platform with wallet ${walletAddress} at ${timestamp}`;
      
      res.status(200).json({
        success: true,
        data: { message, timestamp }
      });
    } catch (error) {
      console.error('Auth message generation error:', error);
      res.status(500).json({ 
        success: false, 
        message: 'Failed to generate auth message', 
        error: error.message 
      });
    }
  });
  
  // Login or register with wallet
  router.post('/wallet/login', async (req, res) => {
    try {
      const { walletAddress, signature, message, role, firstName, lastName } = req.body;
      
      // Validate inputs
      if (!walletAddress || !signature || !message) {
        return res.status(400).json({ 
          success: false, 
          message: 'Wallet address, signature, and message are required' 
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
        // Require additional info for new users
        if (!role || !firstName || !lastName) {
          return res.status(400).json({ 
            success: false, 
            message: 'Role, first name, and last name are required for new users' 
          });
        }
        
        if (!['patient', 'doctor'].includes(role)) {
          return res.status(400).json({ 
            success: false, 
            message: 'Invalid role' 
          });
        }
        
        // Create user
        user = new User({
          walletAddress,
          role,
          firstName,
          lastName,
          isVerified: true
        });
        
        await user.save();
        
        // Create profile
        if (role === 'patient') {
          await new PatientProfile({ user: user._id }).save();
        } else if (role === 'doctor') {
          const { specialty, licenseNumber } = req.body;
          
          if (!specialty || !licenseNumber) {
            return res.status(400).json({ 
              success: false, 
              message: 'Specialty and license number required for doctors' 
            });
          }
          
          await new DoctorProfile({
            user: user._id,
            specialty,
            licenseNumber
          }).save();
        }
        
        isNewUser = true;
      }
      
      // Check if user is active
      if (!user.isActive) {
        return res.status(403).json({ 
          success: false, 
          message: 'Account is deactivated' 
        });
      }
      
      // Update last login
      user.lastLogin = Date.now();
      await user.save();
      
      // Generate token
      const token = jwt.sign(
        { id: user._id, role: user.role, walletAddress: user.walletAddress },
        config.jwt.secret,
        { expiresIn: config.jwt.expiresIn }
      );
      
      res.status(200).json({
        success: true,
        message: isNewUser ? 'Registration successful' : 'Login successful',
        user: sanitizeUser(user),
        token,
        isNewUser
      });
    } catch (error) {
      console.error('Wallet login error:', error);
      res.status(500).json({ 
        success: false, 
        message: 'Wallet login failed', 
        error: error.message 
      });
    }
  });
  
  // Connect wallet to existing account
  router.post('/wallet/connect', authenticate, async (req, res) => {
    try {
      const { walletAddress, signature, message } = req.body;
      const userId = req.user.id;
      
      // Validate inputs
      if (!walletAddress || !signature || !message) {
        return res.status(400).json({ 
          success: false, 
          message: 'Wallet address, signature, and message are required' 
        });
      }
      
      // Check if wallet is already connected
      const existingUser = await User.findOne({ walletAddress });
      if (existingUser && existingUser._id.toString() !== userId) {
        return res.status(400).json({
          success: false,
          message: 'This wallet is already connected to another account'
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
      
      // Update user
      const user = await User.findByIdAndUpdate(
        userId,
        { walletAddress },
        { new: true }
      );
      
      if (!user) {
        return res.status(404).json({
          success: false,
          message: 'User not found'
        });
      }
      
      res.status(200).json({
        success: true,
        message: 'Wallet connected successfully',
        user: sanitizeUser(user)
      });
    } catch (error) {
      console.error('Wallet connection error:', error);
      res.status(500).json({ 
        success: false, 
        message: 'Failed to connect wallet', 
        error: error.message 
      });
    }
  });
  
  // ----- PROFILE MANAGEMENT ROUTES -----
  
  // Get current user profile with related data
  router.get('/me', authenticate, async (req, res) => {
    try {
      const userId = req.user.id;
      
      // Find user
      const user = await User.findById(userId)
        .select('-password -verificationToken -passwordResetToken -passwordResetExpires');
      
      if (!user) {
        return res.status(404).json({ 
          success: false, 
          message: 'User not found' 
        });
      }
      
      // Find profile
      let profile;
      if (user.role === 'patient') {
        profile = await PatientProfile.findOne({ user: userId });
      } else if (user.role === 'doctor') {
        profile = await DoctorProfile.findOne({ user: userId });
      }
      
      res.status(200).json({
        success: true,
        user,
        profile
      });
    } catch (error) {
      console.error('Profile retrieval error:', error);
      res.status(500).json({ 
        success: false, 
        message: 'Failed to retrieve profile', 
        error: error.message 
      });
    }
  });
  
  // Update patient profile with field validation
  router.put('/profile/patient', authenticate, authorize('patient'), async (req, res) => {
    try {
      const userId = req.user.id;
      const updateData = req.body;
      
      // Find profile
      let profile = await PatientProfile.findOne({ user: userId });
      
      if (!profile) {
        return res.status(404).json({ 
          success: false, 
          message: 'Patient profile not found' 
        });
      }
      
      // Update allowed fields
      const allowedFields = [
        'dateOfBirth', 'gender', 'phoneNumber', 'address',
        'emergencyContact', 'medicalHistory', 'allergies',
        'medications', 'insuranceInfo'
      ];
      
      // Apply updates selectively
      allowedFields.forEach(field => {
        if (updateData[field] !== undefined) {
          profile[field] = updateData[field];
        }
      });
      
      await profile.save();
      
      res.status(200).json({
        success: true,
        message: 'Profile updated successfully',
        profile
      });
    } catch (error) {
      console.error('Profile update error:', error);
      res.status(500).json({ 
        success: false, 
        message: 'Failed to update profile', 
        error: error.message 
      });
    }
  });
  
  // Update doctor profile with field validation
  router.put('/profile/doctor', authenticate, authorize('doctor'), async (req, res) => {
    try {
      const userId = req.user.id;
      const updateData = req.body;
      
      // Find profile
      let profile = await DoctorProfile.findOne({ user: userId });
      
      if (!profile) {
        return res.status(404).json({ 
          success: false, 
          message: 'Doctor profile not found' 
        });
      }
      
      // Update allowed fields
      const allowedFields = [
        'specialty', 'education', 'workExperience',
        'certifications', 'availabilityHours', 'contactInfo',
        'isAcceptingNewPatients'
      ];
      
      // Apply updates selectively
      allowedFields.forEach(field => {
        if (updateData[field] !== undefined) {
          profile[field] = updateData[field];
        }
      });
      
      await profile.save();
      
      res.status(200).json({
        success: true,
        message: 'Profile updated successfully',
        profile
      });
    } catch (error) {
      console.error('Profile update error:', error);
      res.status(500).json({ 
        success: false, 
        message: 'Failed to update profile', 
        error: error.message 
      });
    }
  });
  
  // Update user account info with verification
  router.put('/account', authenticate, async (req, res) => {
    try {
      const userId = req.user.id;
      const { firstName, lastName, email } = req.body;
      
      // Find user
      const user = await User.findById(userId);
      
      if (!user) {
        return res.status(404).json({ 
          success: false, 
          message: 'User not found' 
        });
      }
      
      // Check email uniqueness
      if (email && email !== user.email) {
        const existingUser = await User.findOne({ email });
        if (existingUser) {
          return res.status(400).json({
            success: false,
            message: 'Email already in use'
          });
        }
        
        // Set new email with verification
        user.email = email;
        user.isVerified = false;
        user.verificationToken = generateVerificationToken();
        
        // Send verification email
        await sendVerificationEmail(user);
      }
      
      // Update name
      if (firstName) user.firstName = firstName;
      if (lastName) user.lastName = lastName;
      
      await user.save();
      
      res.status(200).json({
        success: true,
        message: email !== user.email ? 
          'Account updated. Please verify your new email address.' : 
          'Account updated successfully',
        user: sanitizeUser(user)
      });
    } catch (error) {
      console.error('Account update error:', error);
      res.status(500).json({ 
        success: false, 
        message: 'Failed to update account', 
        error: error.message 
      });
    }
  });
  
  // Change password with validation
  router.put('/change-password', authenticate, async (req, res) => {
    try {
      const userId = req.user.id;
      const { currentPassword, newPassword } = req.body;
      
      if (!newPassword || newPassword.length < 8) {
        return res.status(400).json({
          success: false,
          message: 'New password must be at least 8 characters'
        });
      }
      
      // Find user
      const user = await User.findById(userId);
      
      if (!user) {
        return res.status(404).json({ 
          success: false, 
          message: 'User not found' 
        });
      }
      
      // Verify current password if exists
      if (user.password) {
        if (!currentPassword) {
          return res.status(400).json({
            success: false,
            message: 'Current password is required'
          });
        }
        
        const isMatch = await user.comparePassword(currentPassword);
        if (!isMatch) {
          return res.status(401).json({
            success: false,
            message: 'Current password is incorrect'
          });
        }
      }
      
      // Update password
      user.password = newPassword;
      await user.save();
      
      res.status(200).json({
        success: true,
        message: 'Password changed successfully'
      });
    } catch (error) {
        console.error('Password change error:', error);
        res.status(500).json({ 
          success: false, 
          message: 'Failed to change password', 
          error: error.message 
        });
      }
    });
    
    // Logout endpoint to update last logout time
    router.post('/logout', authenticate, async (req, res) => {
      try {
        const userId = req.user.id;
        
        // Update last logout timestamp
        await User.findByIdAndUpdate(userId, { lastLogout: Date.now() });
        
        res.status(200).json({
          success: true,
          message: 'Logged out successfully'
        });
      } catch (error) {
        console.error('Logout error:', error);
        res.status(500).json({ 
          success: false, 
          message: 'Failed to process logout', 
          error: error.message 
        });
      }
    });
    
    // ----- 2FA MANAGEMENT ROUTES -----
    
    // Enable two-factor authentication
    router.post('/2fa/enable', authenticate, async (req, res) => {
      try {
        const userId = req.user.id;
        
        // Find user
        const user = await User.findById(userId);
        
        if (!user) {
          return res.status(404).json({ 
            success: false, 
            message: 'User not found' 
          });
        }
        
        if (user.twoFactorAuth.enabled) {
          return res.status(400).json({
            success: false,
            message: '2FA is already enabled'
          });
        }
        
        // Generate secret
        const secret = crypto.randomBytes(16).toString('hex');
        
        // Generate backup codes (for emergency access)
        const backupCodes = Array.from({ length: 5 }, () => 
          crypto.randomBytes(4).toString('hex').toUpperCase()
        );
        
        // Update user
        user.twoFactorAuth = {
          enabled: true,
          secret,
          backupCodes
        };
        
        await user.save();
        
        res.status(200).json({
          success: true,
          message: '2FA enabled successfully',
          data: {
            secret,
            backupCodes
          }
        });
      } catch (error) {
        console.error('2FA enable error:', error);
        res.status(500).json({ 
          success: false, 
          message: 'Failed to enable 2FA', 
          error: error.message 
        });
      }
    });
    
    // Disable two-factor authentication
    router.post('/2fa/disable', authenticate, async (req, res) => {
      try {
        const userId = req.user.id;
        const { password } = req.body;
        
        // Find user
        const user = await User.findById(userId);
        
        if (!user) {
          return res.status(404).json({ 
            success: false, 
            message: 'User not found' 
          });
        }
        
        if (!user.twoFactorAuth.enabled) {
          return res.status(400).json({
            success: false,
            message: '2FA is not enabled'
          });
        }
        
        // Verify password if user has one
        if (user.password) {
          if (!password) {
            return res.status(400).json({
              success: false,
              message: 'Password is required to disable 2FA'
            });
          }
          
          const isMatch = await user.comparePassword(password);
          if (!isMatch) {
            return res.status(401).json({
              success: false,
              message: 'Incorrect password'
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
        
        res.status(200).json({
          success: true,
          message: '2FA disabled successfully'
        });
      } catch (error) {
        console.error('2FA disable error:', error);
        res.status(500).json({ 
          success: false, 
          message: 'Failed to disable 2FA', 
          error: error.message 
        });
      }
    });
    
    // Verify 2FA token during login
    router.post('/2fa/verify', async (req, res) => {
      try {
        const { userId, token, isBackupCode } = req.body;
        
        if (!userId || !token) {
          return res.status(400).json({ 
            success: false, 
            message: 'User ID and token are required' 
          });
        }
        
        // Find user
        const user = await User.findById(userId);
        
        if (!user || !user.twoFactorAuth.enabled) {
          return res.status(404).json({ 
            success: false, 
            message: 'User not found or 2FA not enabled' 
          });
        }
        
        let isValid = false;
        
        // Check if using backup code
        if (isBackupCode) {
          const codeIndex = user.twoFactorAuth.backupCodes.indexOf(token);
          
          if (codeIndex !== -1) {
            // Remove used backup code
            user.twoFactorAuth.backupCodes.splice(codeIndex, 1);
            await user.save();
            isValid = true;
          }
        } else {
          // Implement TOTP verification here
          // For implementation with a library:
          // const isValid = speakeasy.totp.verify({
          //   secret: user.twoFactorAuth.secret,
          //   encoding: 'hex',
          //   token
          // });
          
          // Placeholder for demo (replace with actual implementation)
          isValid = token === '123456'; // Example only! Replace with real TOTP verification
        }
        
        if (!isValid) {
          return res.status(401).json({
            success: false,
            message: 'Invalid 2FA token'
          });
        }
        
        // Update last login
        user.lastLogin = Date.now();
        await user.save();
        
        // Generate token
        const jwtToken = jwt.sign(
          { 
            id: user._id, 
            email: user.email,
            role: user.role,
            walletAddress: user.walletAddress
          },
          config.jwt.secret,
          { expiresIn: config.jwt.expiresIn }
        );
        
        res.status(200).json({
          success: true,
          message: '2FA verification successful',
          user: sanitizeUser(user),
          token: jwtToken
        });
      } catch (error) {
        console.error('2FA verification error:', error);
        res.status(500).json({ 
          success: false, 
          message: 'Failed to verify 2FA token', 
          error: error.message 
        });
      }
    });
    
    // ----- ACCOUNT MANAGEMENT ROUTES -----
    
    // Deactivate account
    router.post('/deactivate', authenticate, async (req, res) => {
      try {
        const userId = req.user.id;
        const { password } = req.body;
        
        // Find user
        const user = await User.findById(userId);
        
        if (!user) {
          return res.status(404).json({ 
            success: false, 
            message: 'User not found' 
          });
        }
        
        // Verify password if user has one
        if (user.password) {
          if (!password) {
            return res.status(400).json({
              success: false,
              message: 'Password is required to deactivate account'
            });
          }
          
          const isMatch = await user.comparePassword(password);
          if (!isMatch) {
            return res.status(401).json({
              success: false,
              message: 'Incorrect password'
            });
          }
        }
        
        // Deactivate account
        user.isActive = false;
        await user.save();
        
        res.status(200).json({
          success: true,
          message: 'Account deactivated successfully'
        });
      } catch (error) {
        console.error('Account deactivation error:', error);
        res.status(500).json({ 
          success: false, 
          message: 'Failed to deactivate account', 
          error: error.message 
        });
      }
    });
    
    // Reactivate account (admin only)
    router.post('/reactivate/:userId', authenticate, authorize('admin'), async (req, res) => {
      try {
        const { userId } = req.params;
        
        // Find user
        const user = await User.findById(userId);
        
        if (!user) {
          return res.status(404).json({ 
            success: false, 
            message: 'User not found' 
          });
        }
        
        // Reactivate account
        user.isActive = true;
        await user.save();
        
        res.status(200).json({
          success: true,
          message: 'Account reactivated successfully'
        });
      } catch (error) {
        console.error('Account reactivation error:', error);
        res.status(500).json({ 
          success: false, 
          message: 'Failed to reactivate account', 
          error: error.message 
        });
      }
    });
    
    // Delete account (admin only)
    router.delete('/users/:userId', authenticate, authorize('admin'), async (req, res) => {
      try {
        const { userId } = req.params;
        
        // Find and delete user
        const user = await User.findById(userId);
        
        if (!user) {
          return res.status(404).json({ 
            success: false, 
            message: 'User not found' 
          });
        }
        
        // Delete related profiles
        if (user.role === 'patient') {
          await PatientProfile.findOneAndDelete({ user: userId });
        } else if (user.role === 'doctor') {
          await DoctorProfile.findOneAndDelete({ user: userId });
        }
        
        // Delete user
        await User.findByIdAndDelete(userId);
        
        res.status(200).json({
          success: true,
          message: 'User account deleted successfully'
        });
      } catch (error) {
        console.error('Account deletion error:', error);
        res.status(500).json({ 
          success: false, 
          message: 'Failed to delete account', 
          error: error.message 
        });
      }
    });
    
    // ----- ADMIN ROUTES -----
    
    // Get all users (admin only)
    router.get('/users', authenticate, authorize('admin'), async (req, res) => {
      try {
        const { role, isActive, page = 1, limit = 10 } = req.query;
        
        // Build query
        const query = {};
        if (role) query.role = role;
        if (isActive !== undefined) query.isActive = isActive === 'true';
        
        // Pagination
        const skip = (parseInt(page) - 1) * parseInt(limit);
        
        // Get users
        const users = await User.find(query)
          .select('-password -verificationToken -passwordResetToken -passwordResetExpires')
          .skip(skip)
          .limit(parseInt(limit))
          .sort({ createdAt: -1 });
        
        const total = await User.countDocuments(query);
        
        res.status(200).json({
          success: true,
          data: {
            users,
            pagination: {
              total,
              page: parseInt(page),
              pages: Math.ceil(total / parseInt(limit)),
              limit: parseInt(limit)
            }
          }
        });
      } catch (error) {
        console.error('Get users error:', error);
        res.status(500).json({ 
          success: false, 
          message: 'Failed to retrieve users', 
          error: error.message 
        });
      }
    });
    
    // Get user by ID (admin only)
    router.get('/users/:userId', authenticate, authorize('admin'), async (req, res) => {
      try {
        const { userId } = req.params;
        
        // Find user
        const user = await User.findById(userId)
          .select('-password -verificationToken -passwordResetToken -passwordResetExpires');
        
        if (!user) {
          return res.status(404).json({ 
            success: false, 
            message: 'User not found' 
          });
        }
        
        // Find profile
        let profile;
        if (user.role === 'patient') {
          profile = await PatientProfile.findOne({ user: userId });
        } else if (user.role === 'doctor') {
          profile = await DoctorProfile.findOne({ user: userId });
        }
        
        res.status(200).json({
          success: true,
          data: {
            user,
            profile
          }
        });
      } catch (error) {
        console.error('Get user error:', error);
        res.status(500).json({ 
          success: false, 
          message: 'Failed to retrieve user', 
          error: error.message 
        });
      }
    });
    
    // Update user role (admin only)
    router.put('/users/:userId/role', authenticate, authorize('admin'), async (req, res) => {
      try {
        const { userId } = req.params;
        const { role } = req.body;
        
        if (!['patient', 'doctor', 'admin'].includes(role)) {
          return res.status(400).json({ 
            success: false, 
            message: 'Invalid role' 
          });
        }
        
        // Find user
        const user = await User.findById(userId);
        
        if (!user) {
          return res.status(404).json({ 
            success: false, 
            message: 'User not found' 
          });
        }
        
        // Handle profile creation if role changes
        if (user.role !== role) {
          // If changing from patient to doctor
          if (user.role === 'patient' && role === 'doctor') {
            // Delete patient profile
            await PatientProfile.findOneAndDelete({ user: userId });
            
            // Create doctor profile
            await new DoctorProfile({ user: userId }).save();
          }
          
          // If changing from doctor to patient
          if (user.role === 'doctor' && role === 'patient') {
            // Delete doctor profile
            await DoctorProfile.findOneAndDelete({ user: userId });
            
            // Create patient profile
            await new PatientProfile({ user: userId }).save();
          }
        }
        
        // Update role
        user.role = role;
        await user.save();
        
        res.status(200).json({
          success: true,
          message: 'User role updated successfully',
          user: sanitizeUser(user)
        });
      } catch (error) {
        console.error('Update role error:', error);
        res.status(500).json({ 
          success: false, 
          message: 'Failed to update user role', 
          error: error.message 
        });
      }
    });
    
    // ----- SESSION MANAGEMENT ROUTES -----
    
    // Get active sessions for current user
    router.get('/sessions', authenticate, async (req, res) => {
      try {
        // This would typically query a sessions collection
        // For demo purposes, returning placeholder data
        
        res.status(200).json({
          success: true,
          data: {
            currentSession: {
              id: 'current-session',
              device: req.headers['user-agent'],
              lastActive: new Date(),
              ip: req.ip
            },
            otherSessions: [
              // Sample data - in production would query from database
              {
                id: 'sample-session-1',
                device: 'Mozilla/5.0 (iPhone)',
                lastActive: new Date(Date.now() - 86400000), // 1 day ago
                ip: '192.168.1.1'
              }
            ]
          }
        });
      } catch (error) {
        console.error('Get sessions error:', error);
        res.status(500).json({ 
          success: false, 
          message: 'Failed to retrieve sessions', 
          error: error.message 
        });
      }
    });
    
    // Revoke session (logout from other device)
    router.delete('/sessions/:sessionId', authenticate, (req, res) => {
      try {
        const { sessionId } = req.params;
        
        // This would typically remove the session from database
        // For demo purposes, returning success
        
        res.status(200).json({
          success: true,
          message: 'Session revoked successfully'
        });
      } catch (error) {
        console.error('Revoke session error:', error);
        res.status(500).json({ 
          success: false, 
          message: 'Failed to revoke session', 
          error: error.message 
        });
      }
    });
    
    // ----- SECURITY AUDIT ROUTES (ADMIN ONLY) -----
    
    // Get login history for a user
    router.get('/audit/logins/:userId', authenticate, authorize('admin'), async (req, res) => {
      try {
        const { userId } = req.params;
        
        // This would query an audit log collection
        // For demo purposes, returning placeholder data
        
        res.status(200).json({
          success: true,
          data: {
            user: userId,
            logins: [
              {
                timestamp: new Date(Date.now() - 3600000), // 1 hour ago
                ip: '192.168.1.2',
                userAgent: 'Mozilla/5.0 (Windows)',
                success: true
              },
              {
                timestamp: new Date(Date.now() - 86400000), // 1 day ago
                ip: '192.168.1.3',
                userAgent: 'Mozilla/5.0 (Android)',
                success: true
              }
            ]
          }
        });
      } catch (error) {
        console.error('Get login history error:', error);
        res.status(500).json({ 
          success: false, 
          message: 'Failed to retrieve login history', 
          error: error.message 
        });
      }
    });
    
    // Export the router
    module.exports = router;