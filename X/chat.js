// backend/services/aiChatbot.js

const axios = require('axios');
const { PartnerIntegration } = require('../config/integrations');
const FluvioClient = require('../utils/fluvioClient');
const { logPatientInteraction } = require('../utils/baseBlockchain');
const { recordScreenData } = require('../utils/screenpipeClient');
const { updatePatientRewards } = require('../utils/monadRewards');

class MedAidChatbot {
  constructor() {
    this.fluvioLogger = new FluvioClient(PartnerIntegration.FLUVIO.apiKey);
    this.context = {};
    this.medicalKnowledgeBase = require('../data/medicalKnowledgeBase.json');
  }

  /**
   * Process a user query through the AI chatbot
   * @param {string} patientId - Unique patient identifier
   * @param {string} query - Patient's message or query
   * @param {object} vitals - Optional current vitals data
   * @returns {object} Response object with message, urgencyLevel, and recommendations
   */
  async processQuery(patientId, query, vitals = null) {
    try {
      // Start performance monitoring with Fluvio
      const sessionId = this.fluvioLogger.startSession('ai_diagnosis');
      
      // Record screen data for AI training and doctor review
      if (PartnerIntegration.SCREENPIPE.enabled) {
        await recordScreenData({
          patientId,
          timestamp: new Date(),
          interaction: 'chatbot_query',
          queryContent: query
        });
      }

      // Retrieve patient context from previous interactions
      const patientContext = await this.getPatientContext(patientId);
      
      // Prepare the prompt with context and current query
      const aiPrompt = this.preparePrompt(query, patientContext, vitals);
      
      // Send to AI service (using Groq in this example)
      const response = await this.sendToAI(aiPrompt);
      
      // Log the interaction for audit trail using Base blockchain
      if (PartnerIntegration.BASE.enabled) {
        await logPatientInteraction({
          patientId,
          queryType: 'chatbot',
          timestamp: new Date(),
          queryHash: this.hashContent(query),
          responseHash: this.hashContent(response.message)
        });
      }
      
      // Award engagement points through Monad
      if (PartnerIntegration.MONAD.enabled && response.engagementScore > 0) {
        await updatePatientRewards(patientId, {
          action: 'chatbot_interaction',
          points: response.engagementScore,
          healthCategory: response.category || 'general'
        });
      }
      
      // End performance monitoring
      this.fluvioLogger.endSession(sessionId, {
        processTime: response.processingTime,
        queryLength: query.length,
        responseLength: response.message.length,
        urgencyLevel: response.urgencyLevel
      });
      
      return response;
    } catch (error) {
      this.fluvioLogger.logError('ai_chatbot_error', {
        error: error.message,
        patientId,
        query
      });
      
      return {
        message: "I'm sorry, I'm having trouble processing your request right now. Please try again or contact medical support if this is urgent.",
        urgencyLevel: "unknown",
        recommendations: [
          "Try rephrasing your question",
          "Contact your doctor directly if this is urgent"
        ]
      };
    }
  }

  /**
   * Prepare the AI prompt with context and patient data
   */
  preparePrompt(query, patientContext, vitals) {
    let prompt = `You are MedAid, an AI healthcare assistant. Consider the following:
    
PATIENT HISTORY: ${JSON.stringify(patientContext.history || {})}
CURRENT MEDICATIONS: ${JSON.stringify(patientContext.medications || [])}
ALLERGIES: ${JSON.stringify(patientContext.allergies || [])}
RECENT INTERACTIONS: ${JSON.stringify(patientContext.recentInteractions || [])}
`;

    // Add vitals if available
    if (vitals) {
      prompt += `\nCURRENT VITALS: ${JSON.stringify(vitals)}`;
    }

    prompt += `\n\nPATIENT QUERY: ${query}
    
Provide a helpful, accurate response. If this appears to be a medical emergency, clearly flag it as urgent. 
Include:
1. A direct answer to the patient's question
2. Any relevant health recommendations
3. An urgency assessment (low, medium, high, emergency)
4. Whether the patient should seek professional medical advice`;

    return prompt;
  }

  /**
   * Send the prepared prompt to an AI service
   */
  async sendToAI(prompt) {
    const startTime = Date.now();
    
    try {
      const aiResponse = await axios.post(PartnerIntegration.AI_SERVICE.endpoint, {
        prompt,
        temperature: 0.2,
        max_tokens: 500
      }, {
        headers: {
          'Authorization': `Bearer ${PartnerIntegration.AI_SERVICE.apiKey}`,
          'Content-Type': 'application/json'
        }
      });
      
      const processingTime = Date.now() - startTime;
      
      // Process and structure the AI response
      return this.processAIResponse(aiResponse.data.choices[0].text, processingTime);
    } catch (error) {
      this.fluvioLogger.logError('ai_service_error', {
        error: error.message,
        prompt: prompt.substring(0, 100) + '...'
      });
      
      throw new Error('Failed to get response from AI service');
    }
  }

  /**
   * Process and structure the raw AI response
   */
  processAIResponse(rawResponse, processingTime) {
    // Extract urgency level with regex
    const urgencyMatch = rawResponse.match(/urgency[^\w]+(low|medium|high|emergency)/i);
    const urgencyLevel = urgencyMatch ? urgencyMatch[1].toLowerCase() : 'medium';
    
    // Extract recommendations
    const recommendationSection = rawResponse.match(/recommendations?:(.+?)(\n\n|\n*$)/is);
    const recommendations = recommendationSection 
      ? recommendationSection[1].split(/\d+\./).filter(Boolean).map(r => r.trim())
      : [];
    
    // Clean up the main message
    let message = rawResponse
      .replace(/urgency[^\n]+/i, '')
      .replace(/recommendations?:(.+?)(\n\n|\n*$)/is, '')
      .trim();
    
    // Check for emergency keywords
    const isEmergency = this.checkForEmergency(rawResponse);
    
    // Determine engagement score for rewards
    const engagementScore = this.calculateEngagementScore(rawResponse, urgencyLevel);
    
    // Categorize the health topic
    const category = this.categorizeHealthTopic(rawResponse);
    
    return {
      message,
      urgencyLevel: isEmergency ? 'emergency' : urgencyLevel,
      recommendations,
      processingTime,
      engagementScore,
      category,
      timestamp: new Date()
    };
  }

  /**
   * Get patient context from database
   */
  async getPatientContext(patientId) {
    // This would connect to your patient database
    // For hackathon purposes, you might use mock data
    return {
      history: {
        conditions: ['seasonal allergies', 'mild hypertension'],
        recentAppointments: [
          { date: '2025-03-15', reason: 'Annual checkup' }
        ]
      },
      medications: [
        { name: 'Lisinopril', dosage: '10mg', frequency: 'daily' }
      ],
      allergies: ['Penicillin'],
      recentInteractions: [
        { date: '2025-04-10', query: 'Can I take Tylenol with my blood pressure medication?' }
      ]
    };
  }

  /**
   * Check for emergency medical situations in the text
   */
  checkForEmergency(text) {
    const emergencyKeywords = [
      'chest pain', 'difficulty breathing', 'severe bleeding',
      'unconscious', 'stroke', 'heart attack', 'seizure',
      'anaphylaxis', 'severe allergic reaction', 'emergency'
    ];
    
    return emergencyKeywords.some(keyword => 
      text.toLowerCase().includes(keyword.toLowerCase())
    );
  }

  /**
   * Calculate engagement score for the Monad rewards system
   */
  calculateEngagementScore(response, urgency) {
    let score = 1; // Base score for interaction
    
    // Higher scores for more detailed responses
    score += Math.min(5, Math.floor(response.length / 200));
    
    // Higher scores for addressing urgent issues
    if (urgency === 'high') score += 3;
    if (urgency === 'emergency') score += 5;
    
    return score;
  }

  /**
   * Categorize the health topic for analytics and rewards
   */
  categorizeHealthTopic(text) {
    const categories = {
      'heart': ['heart', 'cardiac', 'blood pressure', 'cholesterol'],
      'respiratory': ['lung', 'breathing', 'asthma', 'respiratory'],
      'digestive': ['stomach', 'digestion', 'bowel', 'intestine', 'digestive'],
      'mental': ['anxiety', 'depression', 'stress', 'mental health'],
      'nutrition': ['diet', 'food', 'nutrition', 'weight'],
      'sleep': ['sleep', 'insomnia', 'fatigue'],
      'fitness': ['exercise', 'workout', 'fitness', 'activity']
    };
    
    for (const [category, keywords] of Object.entries(categories)) {
      if (keywords.some(keyword => text.toLowerCase().includes(keyword))) {
        return category;
      }
    }
    
    return 'general';
  }

  /**
   * Simple hash function for content
   */
  hashContent(content) {
    // In a production app, use a proper crypto library
    let hash = 0;
    for (let i = 0; i < content.length; i++) {
      hash = ((hash << 5) - hash) + content.charCodeAt(i);
      hash |= 0;
    }
    return hash.toString(16);
  }
}

module.exports = new MedAidChatbot();