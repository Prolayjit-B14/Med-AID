        // Chat is initially hidden
        let chatVisible = false;
        let conversationStarted = false;
        
        // Hardcoded API key and model selection
        // IMPORTANT: Replace "YOUR_GROQ_API_KEY_HERE" with your actual Groq API key
        const apiKey = "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";
        const selectedModel = "llama3-8b-8192";  // You can change this to any Groq model you prefer
        
        // Toggle chat visibility
        function toggleChat() {
            chatVisible = !chatVisible;
            document.getElementById('chat-test').style.display = chatVisible ? 'block' : 'none';
            
            // Initialize chat if it's the first time opening
            if (chatVisible && !conversationStarted) {
                initChat();
                conversationStarted = true;
            }
        }
        
        // Initialize chat with welcome message
        function initChat() {
            const chatStart = document.getElementById('chatStart');
            chatStart.innerHTML = '';
            
            // Add welcome messages
            addBotMessage("Hello 👋");
            
            setTimeout(() => {
                addBotMessage("Welcome to MedBot, your 24/7 medical assistant powered by Groq AI. I'm your AI health companion. How can I assist you today?");
            }, 500);
            
            setTimeout(() => {
                // Add category buttons
                addBotMessage("You can select one of these common topics or type your question:");
                
                const categories = document.createElement('div');
                categories.className = 'health-category';
                
                const topics = [
                    "First Aid", 
                    "Symptoms", 
                    "Medications", 
                    "Find a Doctor", 
                    "Emergency Help",
                    "Health Tips"
                ];
                
                topics.forEach(topic => {
                    const btn = document.createElement('button');
                    btn.className = 'category-btn';
                    btn.textContent = topic;
                    btn.onclick = () => handleCategorySelect(topic);
                    categories.appendChild(btn);
                });
                
                chatStart.appendChild(categories);
                
                // Scroll to bottom
                chatStart.scrollTop = chatStart.scrollHeight;
            }, 1000);
        }
        
        // Handle category selection
        function handleCategorySelect(category) {
            addUserMessage(category);
            
            // Show typing indicator
            showTypingIndicator();
            
            // For category selections, we'll use the Groq API for more dynamic responses
            const prompt = `You are a medical assistant chatbot. The user has selected the category "${category}". 
            Provide a helpful response about this medical topic. Keep your response brief and conversational. 
            If this is about "First Aid", suggest some common first aid topics they might want to learn about. 
            If this is about emergency situations, remind them to call emergency services for serious issues.`;
            
            callGroqApi(prompt).then(response => {
                removeTypingIndicator();
                
                // Process AI response
                if (response) {
                    // Split the response into paragraphs for better readability
                    const paragraphs = response.split('\n').filter(p => p.trim() !== '');
                    paragraphs.forEach(p => {
                        addBotMessage(p);
                    });
                    
                    // If First Aid was selected, add clickable topics
                    if (category === "First Aid") {
                        const firstAidTopics = document.createElement('div');
                        firstAidTopics.className = 'health-category';
                        
                        const topics = ["Cuts & Wounds", "Burns", "Choking", "CPR Basics", "Sprains"];
                        
                        topics.forEach(topic => {
                            const btn = document.createElement('button');
                            btn.className = 'category-btn';
                            btn.textContent = topic;
                            btn.onclick = () => handleFirstAidTopic(topic);
                            firstAidTopics.appendChild(btn);
                        });
                        
                        document.getElementById('chatStart').appendChild(firstAidTopics);
                    }
                } else {
                    addBotMessage("I'm having trouble connecting to my AI services. Please try again later.");
                }
            }).catch(error => {
                removeTypingIndicator();
                addBotMessage("Sorry, I encountered an error when processing your request. Please try again later.");
                console.error("API error:", error);
            });
        }
        
        // Handle first aid topics
        function handleFirstAidTopic(topic) {
            addUserMessage(topic);
            
            // Show typing indicator
            showTypingIndicator();
            
            const prompt = `You are a medical assistant chatbot specializing in first aid information. 
            Provide accurate, concise first aid instructions for "${topic}". 
            Format your response as a step-by-step guide with bullet points where appropriate. 
            Include when the person should seek professional medical attention.`;
            
            callGroqApi(prompt).then(response => {
                removeTypingIndicator();
                
                if (response) {
                    // Split the response into paragraphs
                    const paragraphs = response.split('\n').filter(p => p.trim() !== '');
                    paragraphs.forEach(p => {
                        addBotMessage(p);
                    });
                } else {
                    addBotMessage("I'm having trouble retrieving information on this topic. Please try again later.");
                }
            }).catch(error => {
                removeTypingIndicator();
                addBotMessage("Sorry, I encountered an error when processing your request. Please try again later.");
                console.error("API error:", error);
            });
        }
        
        // Call Groq API
        async function callGroqApi(prompt) {
            try {
                const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${apiKey}`,
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        model: selectedModel,
                        messages: [
                            {
                                role: "system",
                                content: "You are MedBot, a helpful AI medical assistant. Provide accurate, concise, and helpful information about health topics. Always remind users that you're not a replacement for professional medical advice. Keep your responses conversational and brief. Do not use overly technical language unless necessary. Always encourage seeking professional medical help for serious concerns."
                            },
                            {
                                role: "user",
                                content: prompt
                            }
                        ],
                        temperature: 0.5,
                        max_tokens: 500
                    })
                });
                
                if (!response.ok) {
                    const errorData = await response.json();
                    console.error("API error:", errorData);
                    return null;
                }
                
                const data = await response.json();
                return data.choices[0].message.content;
            } catch (error) {
                console.error("Error calling Groq API:", error);
                return null;
            }
        }
        
        // Add a message from the bot
        function addBotMessage(message) {
            const chatStart = document.getElementById('chatStart');
            const msgElement = document.createElement('p');
            msgElement.className = 'msg';
            msgElement.textContent = message;
            chatStart.appendChild(msgElement);
            
            // Scroll to bottom
            chatStart.scrollTop = chatStart.scrollHeight;
        }
        
        // Add a message from the user
        function addUserMessage(message) {
            const chatStart = document.getElementById('chatStart');
            const msgElement = document.createElement('p');
            msgElement.className = 'msg user-msg';
            msgElement.textContent = message;
            chatStart.appendChild(msgElement);
            
            // Scroll to bottom
            chatStart.scrollTop = chatStart.scrollHeight;
        }
        
        // Show typing indicator
        function showTypingIndicator() {
            const chatStart = document.getElementById('chatStart');
            const typingIndicator = document.createElement('div');
            typingIndicator.className = 'msg typing';
            typingIndicator.id = 'typing-indicator';
            
            for (let i = 0; i < 3; i++) {
                const dot = document.createElement('span');
                typingIndicator.appendChild(dot);
            }
            
            chatStart.appendChild(typingIndicator);
            chatStart.scrollTop = chatStart.scrollHeight;
        }
        
        // Remove typing indicator
        function removeTypingIndicator() {
            const typingIndicator = document.getElementById('typing-indicator');
            if (typingIndicator) {
                typingIndicator.remove();
            }
        }
        
        // Send user message
        function sendMessage() {
            const userInput = document.getElementById('user-input');
            const message = userInput.value.trim();
            
            if (message === '') return;
            
            // Add user message to chat
            addUserMessage(message);
            
            // Clear input field
            userInput.value = '';
            
            // Show typing indicator
            showTypingIndicator();
            
            // Process user message with Groq API
            const prompt = `${message}`;
            
            callGroqApi(prompt).then(response => {
                removeTypingIndicator();
                
                if (response) {
                    // Split the response into paragraphs
                    const paragraphs = response.split('\n').filter(p => p.trim() !== '');
                    paragraphs.forEach(p => {
                        addBotMessage(p);
                    });
                } else {
                    addBotMessage("I'm having trouble connecting to my AI services. Please try again later.");
                }
            }).catch(error => {
                removeTypingIndicator();
                addBotMessage("Sorry, I encountered an error when processing your request. Please try again later.");
                console.error("API error:", error);
            });
        }
        
        // Handle Enter key press
        function handleKeyPress(event) {
            if (event.key === 'Enter') {
                sendMessage();
            }
        }


                // Mobile menu toggle
                document.getElementById('mobile-menu-button').addEventListener('click', function() {
                    const menu = document.getElementById('mobile-menu');
                    menu.classList.toggle('hidden');
                });
        
                // Smooth scrolling for anchor links
                document.querySelectorAll('a[href^="#"]').forEach(anchor => {
                    anchor.addEventListener('click', function(e) {
                        e.preventDefault();
                        const targetId = this.getAttribute('href');
                        if (targetId === '#') return;
                        
                        const target = document.querySelector(targetId);
                        if (target) {
                            window.scrollTo({
                                top: target.offsetTop - 100,
                                behavior: 'smooth'
                            });
                            
                            // Close mobile menu if open
                            document.getElementById('mobile-menu').classList.add('hidden');
                        }
                    });
                });