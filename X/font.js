// src/components/ChatBot/MedAidChatbot.jsx

import React, { useState, useEffect, useRef } from 'react';
import axios from 'axios';
import { useAuth } from '../../contexts/AuthContext';
import { useVitals } from '../../contexts/VitalsContext';
import { useRewards } from '../../contexts/RewardsContext';
import ChatMessage from './ChatMessage';
import LoadingIndicator from '../common/LoadingIndicator';
import EmergencyAlertModal from '../alerts/EmergencyAlertModal';
import { ToastContainer, toast } from 'react-toastify';

const MedAidChatbot = () => {
  const [messages, setMessages] = useState([
    {
      id: 1,
      text: "Hello! I'm MedAid, your healthcare assistant. How can I help you today?",
      sender: 'bot',
      timestamp: new Date(),
    }
  ]);
  const [inputMessage, setInputMessage] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [showEmergencyAlert, setShowEmergencyAlert] = useState(false);
  const [emergencyDetails, setEmergencyDetails] = useState({});
  const messagesEndRef = useRef(null);
  
  const { user } = useAuth();
  const { currentVitals } = useVitals();
  const { addRewardPoints } = useRewards();
  
  // Auto-scroll to bottom of messages
  useEffect(() => {
    scrollToBottom();
  }, [messages]);
  
  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };
  
  const handleSendMessage = async (e) => {
    e.preventDefault();
    
    if (!inputMessage.trim()) return;
    
    // Add user message to chat
    const userMessage = {
      id: messages.length + 1,
      text: inputMessage,
      sender: 'user',
      timestamp: new Date()
    };
    
    setMessages(prev => [...prev, userMessage]);
    setInputMessage('');
    setIsLoading(true);
    
    try {
      // Call the AI chatbot API
      const response = await axios.post('/api/chatbot/message', {
        query: inputMessage,
        patientId: user.id,
        vitals: currentVitals || null
      });
      
      const botResponse = response.data;
      
      // Add bot response to chat
      const botMessage = {
        id: messages.length + 2,
        text: botResponse.message,
        sender: 'bot',
        urgencyLevel: botResponse.urgencyLevel,
        recommendations: botResponse.recommendations,
        timestamp: new Date()
      };
      
      setMessages(prev => [...prev, botMessage]);
      
      // Check if this is an emergency
      if (botResponse.urgencyLevel === 'emergency') {
        setEmergencyDetails({
          message: botResponse.message,
          recommendations: botResponse.recommendations
        });
        setShowEmergencyAlert(true);
      }
      else if (botResponse.urgencyLevel === 'high') {
        toast.warning("This might require medical attention. Consider contacting your doctor.", {
          position: "top-right",
          autoClose: 7000
        });
      }
      
      // Add reward points if applicable
      if (botResponse.engagementScore) {
        addRewardPoints(botResponse.engagementScore, 'chatbot_engagement', botResponse.category);
        toast.info(`+${botResponse.engagementScore} health points earned!`, {
          position: "bottom-right",
          autoClose: 3000
        });
      }
      
    } catch (error) {
      console.error('Error sending message to chatbot:', error);
      
      // Add error message
      setMessages(prev => [...prev, {
        id: messages.length + 2,
        text: "I'm sorry, I'm having trouble connecting right now. Please try again shortly.",
        sender: 'bot',
        isError: true,
        timestamp: new Date()
      }]);
      
      toast.error("Connection error. Please try again.", {
        position: "top-right"
      });
    } finally {
      setIsLoading(false);
    }
  };
  
  const handleEmergencyAction = (action) => {
    // Log the emergency action
    axios.post('/api/emergency/log', {
      patientId: user.id,
      action,
      timestamp: new Date(),
      emergencyDetails
    });
    
    setShowEmergencyAlert(false);
  };
  
  const renderTypingIndicator = () => {
    if (!isLoading) return null;
    
    return (
      <div className="flex items-center space-x-2 p-4 bg-gray-50 rounded-lg max-w-md">
        <div className="w-3 h-3 bg-blue-500 rounded-full animate-bounce"></div>
        <div className="w-3 h-3 bg-blue-500 rounded-full animate-bounce" style={{ animationDelay: '0.2s' }}></div>
        <div className="w-3 h-3 bg-blue-500 rounded-full animate-bounce" style={{ animationDelay: '0.4s' }}></div>
      </div>
    );
  };
  
  return (
    <div className="flex flex-col h-full bg-white rounded-xl shadow-lg overflow-hidden">
      <div className="bg-gradient-to-r from-blue-600 to-indigo-700 px-6 py-4">
        <div className="flex items-center">
          <div className="w-10 h-10 rounded-full bg-white/20 flex items-center justify-center">
            <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
          </div>
          <div className="ml-3">
            <h2 className="text-xl font-medium text-white">MedAid Assistant</h2>
            <p className="text-blue-100 text-sm">AI-powered healthcare guidance</p>
          </div>
        </div>
      </div>
      
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {messages.map(message => (
          <ChatMessage 
            key={message.id} 
            message={message} 
          />
        ))}
        {renderTypingIndicator()}
        <div ref={messagesEndRef} />
      </div>
      
      <form onSubmit={handleSendMessage} className="border-t border-gray-200 p-4">
        <div className="flex items-center">
          <input
            type="text"
            value={inputMessage}
            onChange={(e) => setInputMessage(e.target.value)}
            placeholder="Type your health question..."
            className="flex-1 rounded-l-lg border border-gray-300 py-2 px-4 focus:outline-none focus:ring-2 focus:ring-blue-500"
            disabled={isLoading}
          />
          <button 
            type="submit"
            disabled={isLoading || !inputMessage.trim()}
            className="bg-blue-600 text-white rounded-r-lg px-4 py-2 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-700 disabled:bg-blue-400"
          >
            <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8" />
            </svg>
          </button>
        </div>
      </form>
      
      {showEmergencyAlert && (
        <EmergencyAlertModal
          message={emergencyDetails.message}
          recommendations={emergencyDetails.recommendations}
          onCallEmergency={() => handleEmergencyAction('call_emergency')}
          onContactDoctor={() => handleEmergencyAction('contact_doctor')}
          onDismiss={() => handleEmergencyAction('dismissed')}
        />
      )}
      
      <ToastContainer />
    </div>
  );
};

export default MedAidChatbot;