// src/components/ChatBot/ChatMessage.jsx

import React from 'react';
import { formatDistanceToNow } from 'date-fns';

const ChatMessage = ({ message }) => {
  const { text, sender, urgencyLevel, recommendations, timestamp, isError } = message;
  
  const getUrgencyBadge = () => {
    if (!urgencyLevel) return null;
    
    const badges = {
      low: { bg: 'bg-green-100', text: 'text-green-800', label: 'Low Urgency' },
      medium: { bg: 'bg-yellow-100', text: 'text-yellow-800', label: 'Medium Urgency' },
      high: { bg: 'bg-orange-100', text: 'text-orange-800', label: 'High Urgency' },
      emergency: { bg: 'bg-red-100', text: 'text-red-800', label: 'Emergency' }
    };
    
    const badge = badges[urgencyLevel] || badges.medium;
    
    return (
      <span className={`${badge.bg} ${badge.text} text-xs font-medium px-2.5 py-0.5 rounded-full`}>
        {badge.label}
      </span>
    );
  };
  
  const formatTime = (timestamp) => {
    try {
      return formatDistanceToNow(new Date(timestamp), { addSuffix: true });
    } catch (error) {
      return '';
    }
  };
  
  return (
    <div className={`flex ${sender === 'user' ? 'justify-end' : 'justify-start'}`}>
      <div className={`
        max-w-3/4 rounded-lg p-4 
        ${sender === 'user' 
          ? 'bg-blue-500 text-white rounded-br-none' 
          : isError 
            ? 'bg-red-50 border border-red-200 text-gray-800 rounded-bl-none' 
            : 'bg-gray-100 text-gray-800 rounded-bl-none'
        }
      `}>
        <div className="flex flex-col">
          <div className="flex items-center gap-2 mb-1">
            {sender === 'bot' && (
              <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 text-blue-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
            )}
            <span className="text-sm font-medium">
              {sender === 'user' ? 'You' : 'MedAid'}
            </span>
            {getUrgencyBadge()}
          </div>
          
          <div className="text-sm whitespace-pre-wrap">
            {text}
          </div>
          
          {recommendations && recommendations.length > 0 && (
            <div className="mt-3 pt-3 border-t border-gray-200">
              <span className="text-xs font-medium text-gray-500">Recommendations:</span>
              <ul className="mt-1 text-sm list-disc list-inside">
                {recommendations.map((rec, index) => (
                  <li key={index}>{rec}</li>
                ))}
              </ul>
            </div>
          )}
          
          <div className="mt-2 text-xs text-right opacity-70">
            {formatTime(timestamp)}
          </div>
        </div>
      </div>
    </div>
  );
};

export default ChatMessage;