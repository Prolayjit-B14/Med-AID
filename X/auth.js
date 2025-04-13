// This file contains a complete authentication system implementation
// including email/password flow, Base wallet integration, and user profiles

// ----- CONFIGURATION -----
const config = {
    jwt: {
      secret: process.env.JWT_SECRET || 'your-secret-key-here', // Use environment variable in production
      expiresIn: '7d',
    },
    baseWallet: {
      apiEndpoint: process.env.BASE_WALLET_API || 'https://api.base.org/v1',
      appId: process.env.BASE_WALLET_APP_ID,
      appSecret: process.env.BASE_WALLET_APP_SECRET,
    }
  };
  
  // ----- DEPENDENCIES -----
  const express = require('express');
  const bcrypt = require('bcrypt');
  const jwt = require('jsonwebtoken');
  const mongoose = require('mongoose');
  const ethers = require('ethers');
  const router = express.Router();
  
  // ----- DATABASE MODELS -----
  
  // User Schema - Base for both patient and doctor
  const userSchema = new mongoose.Schema({
    email: { 
      type: String, 
      required: true, 
      unique: true,
      trim: true,
      lowercase: true,
      validate: {
        validator: function(v) {
          return /^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/.test(v);
        },
        message: props => `${props.value} is not a valid email address!`
      }
    },
    password: { 
      type: String, 
      required: function() { return !this.walletAddress; } // Required if no wallet
    },
    walletAddress: { 
      type: String, 
      required: function() { return !this.password; }, // Required if no password
      unique: true,
      sparse: true
    },
    role: { 
      type: String, 
      enum: ['patient', 'doctor', 'admin'], 
      required: true 
    },
    firstName: { type: String, required: true },
    lastName: { type: String, required: true },
    createdAt: { type: Date, default: Date.now },
    lastLogin: { type: Date },
    isVerified: { type: Boolean, default: false },
    verificationToken: { type: String },
    passwordResetToken: { type: String },
    passwordResetExpires: { type: Date }
  });
  
  // Virtual for full name
  userSchema.virtual('fullName').get(function() {
    return `${this.firstName} ${this.lastName}`;
  });
  
  // Pre-save hook to hash passwords
  userSchema.pre('save', async function(next) {
    const user = this;
    
    // Only hash the password if it's modified or new
    if (!user.isModified('password')) return next();
    
    try {
      // Generate salt
      const salt = await bcrypt.genSalt(10);
      
      // Hash the password along with the new salt
      const hash = await bcrypt.hash(user.password, salt);
      
      // Override the cleartext password with the hashed one
      user.password = hash;
      next();
    } catch (error) {
      next(error);
    }
  });
  
  // Method to compare passwords
  userSchema.methods.comparePassword = async function(candidatePassword) {
    return bcrypt.compare(candidatePassword, this.password);
  };
  
  // Patient profile schema - extends User
  const patientProfileSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    dateOfBirth: { type: Date },
    gender: { type: String, enum: ['male', 'female', 'other', 'prefer not to say'] },
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
  
  // Doctor profile schema - extends User
  const doctorProfileSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
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
  
  const User = mongoose.model('User', userSchema);
  const PatientProfile = mongoose.model('PatientProfile', patientProfileSchema);
  const DoctorProfile = mongoose.model('DoctorProfile', doctorProfileSchema);
  
  // ----- AUTHENTICATION MIDDLEWARE -----
  
  // Middleware to verify JWT token
  const authenticate = (req, res, next) => {
    try {
      // Get token from header
      const authHeader = req.headers.authorization;
      
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ 
          success: false, 
          message: 'Access denied. No token provided.' 
        });
      }
      
      const token = authHeader.split(' ')[1];
      
      // Verify token
      const decoded = jwt.verify(token, config.jwt.secret);
      
      // Add user to request
      req.user = decoded;
      next();
    } catch (error) {
      return res.status(401).json({ 
        success: false, 
        message: 'Invalid token.' 
      });
    }
  };
  
  // Role-based access control middleware
  const authorize = (...roles) => {
    return (req, res, next) => {
      if (!req.user) {
        return res.status(401).json({ 
          success: false, 
          message: 'Not authenticated.' 
        });
      }
      
      if (!roles.includes(req.user.role)) {
        return res.status(403).json({ 
          success: false, 
          message: 'Not authorized for this action.' 
        });
      }
      
      next();
    };
  };
  
  // ----- BASE WALLET INTEGRATION -----
  
  // Utility to verify Base wallet signatures
  const verifyWalletSignature = async (address, message, signature) => {
    try {
      // Recover the address from the signature
      const signerAddress = ethers.utils.verifyMessage(message, signature);
      
      // Return true if the recovered address matches the claimed address
      return signerAddress.toLowerCase() === address.toLowerCase();
    } catch (error) {
      console.error("Wallet signature verification error:", error);
      return false;
    }
  };
  
  // Connect Base wallet to existing account
  const connectWallet = async (userId, walletAddress, signature) => {
    const message = `Connect wallet ${walletAddress} to your medical platform account`;
    
    const isValidSignature = await verifyWalletSignature(
      walletAddress, 
      message, 
      signature
    );
    
    if (!isValidSignature) {
      throw new Error('Invalid wallet signature');
    }
    
    // Update user with wallet address
    const user = await User.findByIdAndUpdate(
      userId,
      { walletAddress },
      { new: true }
    );
    
    if (!user) {
      throw new Error('User not found');
    }
    
    return user;
  };
  
  // ----- EMAIL VERIFICATION HELPERS -----
  
  // Generate verification token
  const generateVerificationToken = () => {
    return crypto.randomBytes(32).toString('hex');
  };
  
  // Send verification email
  const sendVerificationEmail = async (user) => {
    // Implementation would depend on your email service provider
    // This is a placeholder for the email sending logic
    console.log(`Sending verification email to ${user.email}`);
    console.log(`Verification token: ${user.verificationToken}`);
    
    // In a real implementation, you would use a service like SendGrid, Mailgun, etc.
    // For example, with SendGrid:
    /*
    const msg = {
      to: user.email,
      from: 'noreply@yourapp.com',
      subject: 'Verify Your Email',
      text: `Please verify your email by clicking this link: 
        ${process.env.FRONTEND_URL}/verify-email?token=${user.verificationToken}`,
      html: `<p>Please verify your email by clicking this link:</p>
        <p><a href="${process.env.FRONTEND_URL}/verify-email?token=${user.verificationToken}">
        Verify Email</a></p>`,
    };
    await sgMail.send(msg);
    */
  };
  
  // ----- AUTHENTICATION ROUTES -----
  
  // Register new user (email & password)
  router.post('/register', async (req, res) => {
    try {
      const { email, password, role, firstName, lastName } = req.body;
      
      // Check if user already exists
      const existingUser = await User.findOne({ email });
      if (existingUser) {
        return res.status(400).json({ 
          success: false, 
          message: 'Email already registered' 
        });
      }
      
      // Validate role
      if (!['patient', 'doctor'].includes(role)) {
        return res.status(400).json({ 
          success: false, 
          message: 'Invalid role' 
        });
      }
      
      // Generate verification token
      const verificationToken = generateVerificationToken();
      
      // Create new user
      const user = new User({
        email,
        password,
        role,
        firstName,
        lastName,
        verificationToken
      });
      
      // Save user to database
      await user.save();
      
      // Create profile based on role
      if (role === 'patient') {
        const patientProfile = new PatientProfile({
          user: user._id
        });
        await patientProfile.save();
      } else if (role === 'doctor') {
        // For doctors, we may want to require additional info during registration
        const { specialty, licenseNumber } = req.body;
        
        if (!specialty || !licenseNumber) {
          return res.status(400).json({ 
            success: false, 
            message: 'Specialty and License Number required for doctors' 
          });
        }
        
        const doctorProfile = new DoctorProfile({
          user: user._id,
          specialty,
          licenseNumber
        });
        await doctorProfile.save();
      }
      
      // Send verification email
      await sendVerificationEmail(user);
      
      // Create token (even though email is not verified, for a better UX)
      const token = jwt.sign(
        { id: user._id, email: user.email, role: user.role },
        config.jwt.secret,
        { expiresIn: config.jwt.expiresIn }
      );
      
      // Return success without sending password
      const userResponse = user.toObject();
      delete userResponse.password;
      delete userResponse.verificationToken;
      
      res.status(201).json({
        success: true,
        message: 'Registration successful. Please verify your email.',
        user: userResponse,
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
  
  // Verify email
  router.get('/verify-email/:token', async (req, res) => {
    try {
      const { token } = req.params;
      
      // Find user with the token
      const user = await User.findOne({ verificationToken: token });
      
      if (!user) {
        return res.status(400).json({ 
          success: false, 
          message: 'Invalid verification token' 
        });
      }
      
      // Mark user as verified and remove token
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
      
      // Find user by email
      const user = await User.findOne({ email });
      
      if (!user || !(await user.comparePassword(password))) {
        return res.status(401).json({ 
          success: false, 
          message: 'Invalid email or password' 
        });
      }
      
      // Update last login time
      user.lastLogin = Date.now();
      await user.save();
      
      // Create and sign JWT token
      const token = jwt.sign(
        { id: user._id, email: user.email, role: user.role },
        config.jwt.secret,
        { expiresIn: config.jwt.expiresIn }
      );
      
      // Return user info and token
      const userResponse = user.toObject();
      delete userResponse.password;
      delete userResponse.verificationToken;
      delete userResponse.passwordResetToken;
      delete userResponse.passwordResetExpires;
      
      res.status(200).json({
        success: true,
        message: 'Login successful',
        user: userResponse,
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
  
  // Request password reset
  router.post('/forgot-password', async (req, res) => {
    try {
      const { email } = req.body;
      
      // Find user by email
      const user = await User.findOne({ email });
      
      if (!user) {
        // For security reasons, don't reveal if email exists
        return res.status(200).json({ 
          success: true, 
          message: 'If your email is in our system, you will receive a reset link shortly' 
        });
      }
      
      // Generate reset token and expiry
      const resetToken = crypto.randomBytes(32).toString('hex');
      user.passwordResetToken = resetToken;
      user.passwordResetExpires = Date.now() + 3600000; // 1 hour
      await user.save();
      
      // Send password reset email
      // Implementation would depend on your email service
      
      res.status(200).json({
        success: true,
        message: 'If your email is in our system, you will receive a reset link shortly'
      });
    } catch (error) {
      console.error('Password reset request error:', error);
      res.status(500).json({ 
        success: false, 
        message: 'Password reset request failed', 
        error: error.message 
      });
    }
  });
  
  // Reset password
  router.post('/reset-password/:token', async (req, res) => {
    try {
      const { token } = req.params;
      const { password } = req.body;
      
      // Find user with valid reset token
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
      
      // Update password and clear reset token data
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
  
  // ----- BASE WALLET AUTHENTICATION ROUTES -----
  
  // Generate authentication message for wallet login
  router.post('/wallet/auth-message', (req, res) => {
    try {
      const { walletAddress } = req.body;
      
      if (!walletAddress) {
        return res.status(400).json({ 
          success: false, 
          message: 'Wallet address is required' 
        });
      }
      
      // Generate a nonce or timestamp-based message for the user to sign
      const timestamp = Date.now();
      const message = `Login to medical platform with wallet ${walletAddress} at ${timestamp}`;
      
      res.status(200).json({
        success: true,
        message: 'Authentication message generated',
        data: {
          message,
          timestamp
        }
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
  
  // Login or register with Base wallet
  router.post('/wallet/login', async (req, res) => {
    try {
      const { walletAddress, signature, message, role, firstName, lastName } = req.body;
      
      if (!walletAddress || !signature || !message) {
        return res.status(400).json({ 
          success: false, 
          message: 'Wallet address, signature, and message are required' 
        });
      }
      
      // Verify signature
      const isValidSignature = await verifyWalletSignature(
        walletAddress, 
        message, 
        signature
      );
      
      if (!isValidSignature) {
        return res.status(401).json({ 
          success: false, 
          message: 'Invalid signature' 
        });
      }
      
      // Check if user with wallet exists
      let user = await User.findOne({ walletAddress });
      let isNewUser = false;
      
      // If no user exists, create one
      if (!user) {
        // New registration requires additional info
        if (!role || !firstName || !lastName) {
          return res.status(400).json({ 
            success: false, 
            message: 'Role, first name, and last name are required for new users' 
          });
        }
        
        // Create new user with wallet
        user = new User({
          walletAddress,
          role,
          firstName,
          lastName,
          isVerified: true // Wallet users are auto-verified
        });
        
        await user.save();
        
        // Create appropriate profile
        if (role === 'patient') {
          const patientProfile = new PatientProfile({
            user: user._id
          });
          await patientProfile.save();
        } else if (role === 'doctor') {
          // For doctors we might want to collect more info, but for simplicity:
          const doctorProfile = new DoctorProfile({
            user: user._id,
            specialty: 'Not specified', // This would be collected in the UI
            licenseNumber: 'Not verified' // This would be verified later
          });
          await doctorProfile.save();
        }
        
        isNewUser = true;
      }
      
      // Update last login
      user.lastLogin = Date.now();
      await user.save();
      
      // Generate JWT token
      const token = jwt.sign(
        { id: user._id, role: user.role, walletAddress: user.walletAddress },
        config.jwt.secret,
        { expiresIn: config.jwt.expiresIn }
      );
      
      // Prepare response without sensitive data
      const userResponse = user.toObject();
      delete userResponse.password;
      delete userResponse.verificationToken;
      delete userResponse.passwordResetToken;
      delete userResponse.passwordResetExpires;
      
      res.status(200).json({
        success: true,
        message: isNewUser ? 'Registration successful' : 'Login successful',
        user: userResponse,
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
      
      if (!walletAddress || !signature || !message) {
        return res.status(400).json({ 
          success: false, 
          message: 'Wallet address, signature, and message are required' 
        });
      }
      
      // Check if wallet is already connected to another account
      const existingUser = await User.findOne({ walletAddress });
      if (existingUser && existingUser._id.toString() !== userId) {
        return res.status(400).json({
          success: false,
          message: 'This wallet is already connected to another account'
        });
      }
      
      // Verify signature
      const isValidSignature = await verifyWalletSignature(
        walletAddress, 
        message, 
        signature
      );
      
      if (!isValidSignature) {
        return res.status(401).json({ 
          success: false, 
          message: 'Invalid signature' 
        });
      }
      
      // Update user with wallet address
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
      
      // Prepare response without sensitive data
      const userResponse = user.toObject();
      delete userResponse.password;
      delete userResponse.verificationToken;
      delete userResponse.passwordResetToken;
      delete userResponse.passwordResetExpires;
      
      res.status(200).json({
        success: true,
        message: 'Wallet connected successfully',
        user: userResponse
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
  
  // ----- USER PROFILE ROUTES -----
  
  // Get current user profile
  router.get('/me', authenticate, async (req, res) => {
    try {
      const userId = req.user.id;
      
      // Find user without sensitive information
      const user = await User.findById(userId).select('-password -verificationToken -passwordResetToken -passwordResetExpires');
      
      if (!user) {
        return res.status(404).json({ 
          success: false, 
          message: 'User not found' 
        });
      }
      
      // Find related profile based on role
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
  
  // Update patient profile
  router.put('/profile/patient', authenticate, authorize('patient'), async (req, res) => {
    try {
      const userId = req.user.id;
      const updateData = req.body;
      
      // Find patient profile
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
      
      allowedFields.forEach(field => {
        if (updateData[field] !== undefined) {
          profile[field] = updateData[field];
        }
      });
      
      // Save updated profile
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
  
  // Update doctor profile
  router.put('/profile/doctor', authenticate, authorize('doctor'), async (req, res) => {
    try {
      const userId = req.user.id;
      const updateData = req.body;
      
      // Find doctor profile
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
      
      allowedFields.forEach(field => {
        if (updateData[field] !== undefined) {
          profile[field] = updateData[field];
        }
      });
      
      // Save updated profile
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
  
  // Update user account info (name, email)
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
      
      // Check if email is being changed and if it's unique
      if (email && email !== user.email) {
        const existingUser = await User.findOne({ email });
        if (existingUser) {
          return res.status(400).json({
            success: false,
            message: 'Email already in use'
          });
        }
        user.email = email;
        
        // Require re-verification if email changes
        user.isVerified = false;
        user.verificationToken = generateVerificationToken();
        
        // Send verification email
        await sendVerificationEmail(user);
      }
      
      // Update name if provided
      if (firstName) user.firstName = firstName;
      if (lastName) user.lastName = lastName;
      
      // Save user
      await user.save();
      
      // Prepare response
      const userResponse = user.toObject();
      delete userResponse.password;
      delete userResponse.verificationToken;
      delete userResponse.passwordResetToken;
      delete userResponse.passwordResetExpires;
      
      res.status(200).json({
        success: true,
        message: email !== user.email ? 
          'Account updated. Please verify your new email address.' : 
          'Account updated successfully',
        user: userResponse
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
  
  // Change password
  router.put('/change-password', authenticate, async (req, res) => {
    try {
      const userId = req.user.id;
      const { currentPassword, newPassword } = req.body;
      
      // Find user
      const user = await User.findById(userId);
      
      if (!user) {
        return res.status(404).json({ 
          success: false, 
          message: 'User not found' 
        });
      }
      
      // If user has a password, verify current password
      if (user.password) {
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
  
// ----- EXPORTS -----
module.exports = {
    router,
    authenticate,
    authorize,
    User,
    PatientProfile,
    DoctorProfile,
    connectWallet,
    verifyWalletSignature
  }

  // ----- SESSION MANAGEMENT -----

// Logout (blacklist token)
router.post('/logout', authenticate, async (req, res) => {
    try {
      // In a production app, you would typically add the token to a blacklist
      // or use Redis to track invalidated tokens until they expire
      
      // For this implementation, we'll just update the last logout time
      const userId = req.user.id;
      
      await User.findByIdAndUpdate(userId, {
        $set: { lastLogout: Date.now() }
      });
      
      res.status(200).json({
        success: true,
        message: 'Logout successful'
      });
    } catch (error) {
      console.error('Logout error:', error);
      res.status(500).json({ 
        success: false, 
        message: 'Logout failed', 
        error: error.message 
      });
    }
  });
  
  // Refresh token
  router.post('/refresh-token', async (req, res) => {
    try {
      const { token } = req.body;
      
      if (!token) {
        return res.status(400).json({
          success: false,
          message: 'Token is required'
        });
      }
      
      // Verify existing token
      const decoded = jwt.verify(token, config.jwt.secret);
      
      // Find user
      const user = await User.findById(decoded.id).select('-password -verificationToken -passwordResetToken -passwordResetExpires');
      
      if (!user) {
        return res.status(404).json({
          success: false,
          message: 'User not found'
        });
      }
      
      // Check if token was issued before the user logged out
      if (user.lastLogout && decoded.iat * 1000 < user.lastLogout.getTime()) {
        return res.status(401).json({
          success: false,
          message: 'Token has been invalidated by logout'
        });
      }
      
      // Generate new token
      const newToken = jwt.sign(
        { id: user._id, email: user.email, role: user.role },
        config.jwt.secret,
        { expiresIn: config.jwt.expiresIn }
      );
      
      res.status(200).json({
        success: true,
        message: 'Token refreshed successfully',
        token: newToken,
        user
      });
    } catch (error) {
      console.error('Token refresh error:', error);
      
      if (error.name === 'JsonWebTokenError' || error.name === 'TokenExpiredError') {
        return res.status(401).json({
          success: false,
          message: 'Invalid or expired token'
        });
      }
      
      res.status(500).json({ 
        success: false, 
        message: 'Token refresh failed', 
        error: error.message 
      });
    }
  });
  
  // ----- ADMIN ROUTES -----
  
  // Get all users (admin only)
  router.get('/users', authenticate, authorize('admin'), async (req, res) => {
    try {
      const { role, verified, page = 1, limit = 10 } = req.query;
      
      // Build query
      let query = {};
      
      if (role) query.role = role;
      if (verified !== undefined) query.isVerified = verified === 'true';
      
      // Pagination
      const skip = (page - 1) * limit;
      
      // Find users
      const users = await User.find(query)
        .select('-password -verificationToken -passwordResetToken -passwordResetExpires')
        .skip(skip)
        .limit(parseInt(limit))
        .sort({ createdAt: -1 });
      
      // Count total
      const total = await User.countDocuments(query);
      
      res.status(200).json({
        success: true,
        users,
        pagination: {
          total,
          page: parseInt(page),
          limit: parseInt(limit),
          pages: Math.ceil(total / limit)
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
  
  // Admin: Activate/deactivate user
  router.put('/users/:userId/status', authenticate, authorize('admin'), async (req, res) => {
    try {
      const { userId } = req.params;
      const { isActive } = req.body;
      
      if (isActive === undefined) {
        return res.status(400).json({
          success: false,
          message: 'isActive status is required'
        });
      }
      
      const user = await User.findByIdAndUpdate(
        userId,
        { $set: { isActive: isActive } },
        { new: true }
      ).select('-password -verificationToken -passwordResetToken -passwordResetExpires');
      
      if (!user) {
        return res.status(404).json({
          success: false,
          message: 'User not found'
        });
      }
      
      res.status(200).json({
        success: true,
        message: `User ${isActive ? 'activated' : 'deactivated'} successfully`,
        user
      });
    } catch (error) {
      console.error('User status update error:', error);
      res.status(500).json({ 
        success: false, 
        message: 'Failed to update user status', 
        error: error.message 
      });
    }
  });
  
  // ----- SECURITY ENHANCEMENTS -----
  
  // Add schema field for 2FA
  userSchema.add({
    twoFactorAuth: {
      enabled: { type: Boolean, default: false },
      secret: { type: String },
      backupCodes: [String]
    },
    isActive: { type: Boolean, default: true },
    lastLogout: { type: Date }
  });
  
  // Setup 2FA
  router.post('/2fa/setup', authenticate, async (req, res) => {
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
      
      // Create new secret
      const secret = speakeasy.generateSecret({ length: 20 });
      
      // Generate backup codes
      const backupCodes = [];
      for (let i = 0; i < 5; i++) {
        backupCodes.push(crypto.randomBytes(10).toString('hex'));
      }
      
      // Save to user but don't enable yet
      user.twoFactorAuth = {
        enabled: false,
        secret: secret.base32,
        backupCodes: backupCodes
      };
      
      await user.save();
      
      // Generate QR code
      const otpAuthUrl = speakeasy.otpauthURL({
        secret: secret.ascii,
        label: `MedicalApp:${user.email}`,
        issuer: 'MedicalApp'
      });
      
      res.status(200).json({
        success: true,
        message: '2FA setup initiated',
        secret: secret.base32,
        otpAuthUrl,
        backupCodes
      });
    } catch (error) {
      console.error('2FA setup error:', error);
      res.status(500).json({ 
        success: false, 
        message: 'Failed to setup 2FA', 
        error: error.message 
      });
    }
  });
  
  // Verify and enable 2FA
  router.post('/2fa/verify', authenticate, async (req, res) => {
    try {
      const userId = req.user.id;
      const { token } = req.body;
      
      // Find user
      const user = await User.findById(userId);
      
      if (!user || !user.twoFactorAuth || !user.twoFactorAuth.secret) {
        return res.status(400).json({
          success: false,
          message: '2FA not set up'
        });
      }
      
      // Verify token
      const verified = speakeasy.totp.verify({
        secret: user.twoFactorAuth.secret,
        encoding: 'base32',
        token
      });
      
      if (!verified) {
        return res.status(401).json({
          success: false,
          message: 'Invalid 2FA token'
        });
      }
      
      // Enable 2FA
      user.twoFactorAuth.enabled = true;
      await user.save();
      
      res.status(200).json({
        success: true,
        message: '2FA enabled successfully'
      });
    } catch (error) {
      console.error('2FA verification error:', error);
      res.status(500).json({ 
        success: false, 
        message: 'Failed to verify 2FA', 
        error: error.message 
      });
    }
  });
  
  // ----- ANALYTICS ENDPOINTS -----
  
  // Get user account statistics (admin only)
  router.get('/analytics/users', authenticate, authorize('admin'), async (req, res) => {
    try {
      // Get total counts by role
      const totalUsers = await User.countDocuments();
      const patientCount = await User.countDocuments({ role: 'patient' });
      const doctorCount = await User.countDocuments({ role: 'doctor' });
      const adminCount = await User.countDocuments({ role: 'admin' });
      
      // Get counts by verification status
      const verifiedCount = await User.countDocuments({ isVerified: true });
      const unverifiedCount = await User.countDocuments({ isVerified: false });
      
      // Get counts by wallet status
      const walletConnectedCount = await User.countDocuments({ 
        walletAddress: { $exists: true, $ne: null } 
      });
      
      // Get recent registrations (last 30 days)
      const thirtyDaysAgo = new Date();
      thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
      
      const recentRegistrations = await User.countDocuments({
        createdAt: { $gte: thirtyDaysAgo }
      });
      
      // Get registrations by month (last 6 months)
      const sixMonthsAgo = new Date();
      sixMonthsAgo.setMonth(sixMonthsAgo.getMonth() - 6);
      
      const registrationsByMonth = await User.aggregate([
        {
          $match: {
            createdAt: { $gte: sixMonthsAgo }
          }
        },
        {
          $group: {
            _id: { 
              year: { $year: "$createdAt" },
              month: { $month: "$createdAt" }
            },
            count: { $sum: 1 }
          }
        },
        {
          $sort: { "_id.year": 1, "_id.month": 1 }
        }
      ]);
      
      res.status(200).json({
        success: true,
        stats: {
          total: totalUsers,
          byRole: {
            patient: patientCount,
            doctor: doctorCount,
            admin: adminCount
          },
          byVerification: {
            verified: verifiedCount,
            unverified: unverifiedCount
          },
          walletConnected: walletConnectedCount,
          recentRegistrations,
          registrationsByMonth
        }
      });
    } catch (error) {
      console.error('User analytics error:', error);
      res.status(500).json({ 
        success: false, 
        message: 'Failed to retrieve user analytics', 
        error: error.message 
      });
    }
  });
  
  // ----- EVENT HANDLERS -----
  
  // User events for logging and auditing
  userSchema.post('save', function(doc) {
    // Log user creation or update
    console.log(`User ${doc._id} saved: ${doc.email}`);
    
    // In a production environment, you would emit events
    // that can be consumed by other services for auditing
    // eventEmitter.emit('user:saved', { userId: doc._id, email: doc.email });
  });
  
  userSchema.post('remove', function(doc) {
    // Log user deletion
    console.log(`User ${doc._id} removed: ${doc.email}`);
    
    // eventEmitter.emit('user:removed', { userId: doc._id, email: doc.email });
  });
  
  // ----- MODULE EXPORTS -----
  
  module.exports = {
    router,                // Export router for use in main app
    authenticate,          // Export middleware for other protected routes
    authorize,             // Export role-based authorization middleware
    User,                  // Export models for use in other modules
    PatientProfile,
    DoctorProfile,
    connectWallet,         // Export wallet utility functions
    verifyWalletSignature,
    // Additional utilities and helpers
    generateVerificationToken,
    sendVerificationEmail
  };