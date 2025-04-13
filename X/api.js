// backend/routes/chatbotRoutes.js

const express = require('express');
const router = express.Router();
const medAidChatbot = require('../services/aiChatbot');
const { authenticateUser } = require('../middleware/auth');
const { logToFluvio } = require('../middleware/logging');

// Middleware to authenticate and log API requests
router.use(authenticateUser);
router.use(logToFluvio('chatbot_api'));

/**
 * Process user message through the AI chatbot
 * POST /api/chatbot/message
 */
router.post('/message', async (req, res) => {
  try {
    const { query, patientId, vitals } = req.body;
    
    if (!query || !patientId) {
      return res.status(400).json({ 
        error: 'Missing required parameters' 
      });
    }
    
    // Process the message through the chatbot
    const response = await medAidChatbot.processQuery(patientId, query, vitals);
    
    res.json(response);
  } catch (error) {
    console.error('Chatbot API error:', error);
    res.status(500).json({ 
      error: 'Failed to process message',
      message: "I'm sorry, I'm having trouble connecting right now. Please try again shortly."
    });
  }
});

/**
 * Get conversation history for a patient
 * GET /api/chatbot/history/:patientId
 */
router.get('/history/:patientId', async (req, res) => {
  try {
    const { patientId } = req.params;
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    
    // Implement database query to get conversation history
    // This would connect to your MongoDB or other database
    
    res.json({
      history: [], // Populate from database
      pagination: {
        page,
        limit,
        total: 0 // Total count from database
      }
    });
  } catch (error) {
    console.error('Error fetching chat history:', error);
    res.status(500).json({ error: 'Failed to fetch chat history' });
  }
});

/**
 * Log emergency response actions
 * POST /api/emergency/log
 */
router.post('/emergency/log', async (req, res) => {
  try {
    const { patientId, action, timestamp, emergencyDetails } = req.body;
    
    // Log to monitoring system (Fluvio)
    medAidChatbot.fluvioLogger.logEvent('emergency_action', {
      patientId,
      action,
      timestamp,
      details: emergencyDetails
    });
    
    // For emergency actions, also notify medical staff
    if (action === 'call_emergency') {
      // Implement emergency notification system
      // This could be a separate service that sends SMS/emails to on-call staff
    }
    
    res.json({ success: true });
  } catch (error) {
    console.error('Error logging emergency action:', error);
    res.status(500).json({ error: 'Failed to log emergency action' });
  }
});

module.exports = router;